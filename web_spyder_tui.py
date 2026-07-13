import threading
import urllib.parse
import os
import socket # 1. الترقيع الأول: علاج الـ IPv6 Timeout
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import requests
import requests.exceptions

# --- بداية الترقيع الأول ---
def force_ipv4():
    orig_getaddrinfo = socket.getaddrinfo
    def new_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        return orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
    socket.getaddrinfo = new_getaddrinfo
force_ipv4()
# --- نهاية الترقيع الأول ---


from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Input, Button, DataTable, RichLog, ProgressBar

class WebSpyderPro(App):
    TITLE = "WebSpyder Pro - Final Robust Scanner"
    BINDINGS = [("q", "quit", "Quit App")]
    
    CSS = """
    .input-bar { height: auto; margin-bottom: 1; }
    #url_input { width: 4fr; }
    #scan_btn { width: 1fr; }
    #progress { margin: 1 2; }
    #main-layout { height: 1fr; }
    #table-container { width: 60%; }
    #log-container { width: 40%; border-left: solid $primary; }
    """
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(classes="input-bar"):
            yield Input(placeholder="http://127.0.0.1:9090", id="url_input")
            yield Button("Start Scan", variant="success", id="scan_btn")
        yield ProgressBar(total=100, show_bar=True, show_percentage=True, id="progress")
        with Horizontal(id="main-layout"):
            with Vertical(id="table-container"):
                yield DataTable(id="vuln_table")
            with Vertical(id="log-container"):
                yield RichLog(id="activity_log", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#vuln_table", DataTable)
        table.add_columns("Vulnerability Type", "Severity", "Target URL")
        table.zebra_stripes = True
        
        os.environ['NO_PROXY'] = '*'
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.session.trust_env = False 

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.query_one("#scan_btn", Button).press()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan_btn":
            target_url = self.query_one("#url_input", Input).value.strip()
            if not target_url:
                self.write_log("[bold red][!] Please enter a valid URL.[/bold red]")
                return
            if not target_url.startswith(("http://", "https://")):
                target_url = "http://" + target_url

            self.query_one("#vuln_table", DataTable).clear()
            self.query_one("#activity_log", RichLog).clear()
            self.query_one("#progress", ProgressBar).progress = 0
            
            event.button.disabled = True
            event.button.label = "Scanning..."
            threading.Thread(target=self.run_scanner, args=(target_url,), daemon=True).start()

    def write_log(self, message: str) -> None:
        self.call_from_thread(self.query_one("#activity_log", RichLog).write, message)

    def add_vulnerability(self, vuln_type: str, severity: str, url: str) -> None:
        color = "red" if severity == "High" else "yellow" if severity == "Medium" else "blue"
        styled_severity = f"[{color}]{severity}[/{color}]"
        self.call_from_thread(self.query_one("#vuln_table", DataTable).add_row, vuln_type, styled_severity, url)

    def update_progress(self, value: float) -> None:
        self.call_from_thread(setattr, self.query_one("#progress", ProgressBar), "progress", value)

    def check_sensitive_file(self, path: str, base_url: str):
        test_url = base_url + path
        try:
            res = self.session.get(test_url, timeout=5) 
            if res.status_code == 200 and len(res.text) > 10: 
                return (True, path, test_url)
        except requests.exceptions.Timeout:
            return ("timeout", path, test_url)
        except:
            pass 
        return (False, path, test_url)

    def run_scanner(self, target_url: str) -> None:
        self.write_log(f"[bold blue][*] Connecting to:[/bold blue] {target_url}")
        self.update_progress(5)

        try:
            response = self.session.get(target_url, timeout=15, allow_redirects=True)
            self.write_log("[green][+] Connection established! Analyzing...[/green]")
            self.update_progress(15)
        except requests.exceptions.Timeout:
            self.write_log("[bold red][-] TIMEOUT: Server took too long (>15s).[/bold red]")
            self.update_progress(100)
            self.reset_button()
            return
        except requests.exceptions.ConnectionError:
            self.write_log("[bold red][-] CONNECTION ERROR: Cannot reach the server.[/bold red]")
            self.update_progress(100)
            self.reset_button()
            return
        except Exception as e:
            self.write_log(f"[bold red][-] Unexpected Error: {str(e)}[/bold red]")
            self.update_progress(100)
            self.reset_button()
            return

        # Phase 1
        self.write_log("[yellow][*] Phase 1: Checking Headers...[/yellow]")
        headers_to_check = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        for header in headers_to_check:
            if header not in response.headers:
                self.add_vulnerability(f"Missing {header}", "Low", target_url)
        self.update_progress(30)

        # Phase 2
        self.write_log("[yellow][*] Phase 2: Scanning Files (Parallel)...[/yellow]")
        sensitive_paths = ["/.env", "/.git/HEAD", "/config.json", "/robots.txt"]
        parsed_url = urllib.parse.urlparse(target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.check_sensitive_file, path, base_url): path for path in sensitive_paths}
            for future in as_completed(futures):
                status, path, test_url = future.result()
                if status == True:
                    self.write_log(f" [bold red][!][/bold red] Exposed: {path}")
                    self.add_vulnerability("Sensitive File Exposed", "High", test_url)
                elif status == "timeout":
                    self.write_log(f" [dim][T] Timeout: {path}[/dim]")
                else:
                    self.write_log(f" [dim]- Safe: {path}[/dim]")
        self.update_progress(70)

        # Phase 3
        self.write_log("[yellow][*] Phase 3: Testing XSS on Forms...[/yellow]")
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        self.write_log(f"[green][+] Found {len(forms)} form(s).[/green]")

        xss_payload = "<script>alert('XSS')</script>"
        for form in forms:
            action = form.get("action", "")
            post_url = urllib.parse.urljoin(target_url, action)
            method = form.get("method", "get").lower()

            data = {}
            for index, inp in enumerate(form.find_all("input")):
                name = inp.get("name")
                if name: data[name] = xss_payload
                elif inp.get("type") in ["text", "search"]: data[f"input_{index}"] = xss_payload

            if not data: continue
            try:
                if method == "post":
                    vuln_res = self.session.post(post_url, data=data, timeout=10)
                else:
                    vuln_res = self.session.get(post_url, params=data, timeout=10)
                
                # --- 2. الترقيع الثاني: منع الـ False Positive في الـ XSS ---
                vuln_soup = BeautifulSoup(vuln_res.text, 'html.parser')
                if vuln_soup.find(string=xss_payload):
                    self.add_vulnerability("Reflected XSS (High Confidence)", "Medium", post_url)
                    self.write_log(f" [bold red][!][/bold red] XSS Found on: {post_url}")
                elif xss_payload in vuln_res.text:
                    self.add_vulnerability("Potential XSS (Encoded/Hidden)", "Low", post_url)
                    self.write_log(f" [dim][*] Hidden XSS found in: {post_url}[/dim]")
                # --- نهاية الترقيع الثاني ---

            except:
                continue

        self.update_progress(100)
        self.write_log("[bold green][===] Scan Finished! [===][/bold green]")
        self.reset_button()

    def reset_button(self):
        btn = self.query_one("#scan_btn", Button)
        self.call_from_thread(setattr, btn, "disabled", False)
        self.call_from_thread(setattr, btn, "label", "Start Scan")

if __name__ == "__main__":
    app = WebSpyderPro()
    app.run()
