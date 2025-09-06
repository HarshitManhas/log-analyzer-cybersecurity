"""
Log Analyzer GUI
Tkinter-based graphical user interface for the Log Analyzer application.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import json
from log_analyzer import LogAnalyzer

class LogAnalyzerGUI:
    """Main GUI application for Log Analyzer."""
    
    def __init__(self):
        """Initialize the GUI application."""
        self.root = tk.Tk()
        self.root.title("Log Analyzer for Cybersecurity")
        self.root.geometry("1200x800")
        
        # Initialize the analyzer
        self.analyzer = LogAnalyzer()
        self.current_results = None
        
        # Create GUI components
        self.setup_gui()
        
    def setup_gui(self):
        """Set up the GUI layout and components."""
        # Create main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="Log Analyzer for Cybersecurity", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection")
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # File path entry
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, 
                                   width=80, state="readonly")
        self.file_entry.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        
        # Browse button
        browse_btn = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_btn.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Analyze button
        analyze_btn = ttk.Button(file_frame, text="Analyze Log", command=self.analyze_log)
        analyze_btn.pack(side=tk.RIGHT, padx=(0, 5), pady=5)
        
        # Progress bar
        self.progress_var = tk.StringVar()
        self.progress_var.set("Ready")
        progress_label = ttk.Label(main_frame, textvariable=self.progress_var)
        progress_label.pack(anchor="w")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Summary tab
        self.create_summary_tab()
        
        # IP Analysis tab
        self.create_ip_analysis_tab()
        
        # Security Analysis tab
        self.create_security_tab()
        
        # Traffic Analysis tab
        self.create_traffic_tab()
        
        # Raw Data tab
        self.create_raw_data_tab()
        
        # Export options
        export_frame = ttk.Frame(main_frame)
        export_frame.pack(fill=tk.X, pady=(10, 0))
        
        export_report_btn = ttk.Button(export_frame, text="Export Report", 
                                     command=self.export_report)
        export_report_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        export_json_btn = ttk.Button(export_frame, text="Export JSON", 
                                   command=self.export_json)
        export_json_btn.pack(side=tk.LEFT)
    
    def create_summary_tab(self):
        """Create the summary tab."""
        summary_frame = ttk.Frame(self.notebook)
        self.notebook.add(summary_frame, text="Summary")
        
        # Summary text widget
        self.summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initial text
        self.summary_text.insert(tk.END, "Load a log file to see analysis summary...")
        self.summary_text.config(state=tk.DISABLED)
    
    def create_ip_analysis_tab(self):
        """Create the IP analysis tab."""
        ip_frame = ttk.Frame(self.notebook)
        self.notebook.add(ip_frame, text="IP Analysis")
        
        # Create treeview for IP data
        columns = ('IP Address', 'Count', 'Type', 'Status')
        self.ip_tree = ttk.Treeview(ip_frame, columns=columns, show='headings')
        
        for col in columns:
            self.ip_tree.heading(col, text=col)
            self.ip_tree.column(col, width=150)
        
        # Scrollbar for IP tree
        ip_scrollbar = ttk.Scrollbar(ip_frame, orient=tk.VERTICAL, command=self.ip_tree.yview)
        self.ip_tree.configure(yscrollcommand=ip_scrollbar.set)
        
        self.ip_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        ip_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
    
    def create_security_tab(self):
        """Create the security analysis tab."""
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security Analysis")
        
        # Security alerts
        alerts_label = ttk.Label(security_frame, text="Security Alerts:", 
                               font=("Arial", 12, "bold"))
        alerts_label.pack(anchor="w", padx=5, pady=(5, 0))
        
        self.security_text = scrolledtext.ScrolledText(security_frame, height=10)
        self.security_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Metrics frame
        metrics_frame = ttk.LabelFrame(security_frame, text="Security Metrics")
        metrics_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.metrics_tree = ttk.Treeview(metrics_frame, columns=('Metric', 'Value'), 
                                       show='headings')
        self.metrics_tree.heading('Metric', text='Security Metric')
        self.metrics_tree.heading('Value', text='Count')
        self.metrics_tree.column('Metric', width=200)
        self.metrics_tree.column('Value', width=100)
        
        self.metrics_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_traffic_tab(self):
        """Create the traffic analysis tab."""
        traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(traffic_frame, text="Traffic Analysis")
        
        # Status codes frame
        status_frame = ttk.LabelFrame(traffic_frame, text="HTTP Status Codes")
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_tree = ttk.Treeview(status_frame, columns=('Status Code', 'Count', 'Percentage'), 
                                      show='headings')
        self.status_tree.heading('Status Code', text='Status Code')
        self.status_tree.heading('Count', text='Count')
        self.status_tree.heading('Percentage', text='Percentage')
        
        for col in ('Status Code', 'Count', 'Percentage'):
            self.status_tree.column(col, width=120)
        
        self.status_tree.pack(fill=tk.X, padx=5, pady=5)
        
        # Top URLs frame
        urls_frame = ttk.LabelFrame(traffic_frame, text="Top Requested URLs")
        urls_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.urls_tree = ttk.Treeview(urls_frame, columns=('URL', 'Requests'), 
                                    show='headings')
        self.urls_tree.heading('URL', text='URL/Endpoint')
        self.urls_tree.heading('Requests', text='Request Count')
        self.urls_tree.column('URL', width=400)
        self.urls_tree.column('Requests', width=100)
        
        self.urls_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_raw_data_tab(self):
        """Create the raw data tab."""
        raw_frame = ttk.Frame(self.notebook)
        self.notebook.add(raw_frame, text="Raw Data")
        
        # Raw JSON display
        self.raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.WORD)
        self.raw_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initial text
        self.raw_text.insert(tk.END, "Raw analysis data will appear here...")
        self.raw_text.config(state=tk.DISABLED)
    
    def browse_file(self):
        """Open file dialog to select log file."""
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[
                ("Log files", "*.log"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.file_path_var.set(file_path)
    
    def analyze_log(self):
        """Analyze the selected log file."""
        file_path = self.file_path_var.get()
        
        if not file_path:
            messagebox.showerror("Error", "Please select a log file first.")
            return
        
        # Run analysis in separate thread to prevent GUI freezing
        self.progress_var.set("Analyzing...")
        self.root.update()
        
        thread = threading.Thread(target=self._analyze_thread, args=(file_path,))
        thread.daemon = True
        thread.start()
    
    def _analyze_thread(self, file_path):
        """Thread function for log analysis."""
        try:
            results = self.analyzer.analyze_file(file_path)
            self.current_results = results
            
            # Update GUI in main thread
            self.root.after(0, self._update_results)
            
        except Exception as e:
            error_msg = f"Error analyzing file: {str(e)}"
            self.root.after(0, lambda: messagebox.showerror("Analysis Error", error_msg))
            self.root.after(0, lambda: self.progress_var.set("Error"))
    
    def _update_results(self):
        """Update GUI with analysis results."""
        if not self.current_results:
            return
        
        # Update summary tab
        self.update_summary_tab()
        
        # Update IP analysis tab
        self.update_ip_tab()
        
        # Update security tab
        self.update_security_tab()
        
        # Update traffic tab
        self.update_traffic_tab()
        
        # Update raw data tab
        self.update_raw_data_tab()
        
        self.progress_var.set("Analysis complete")
        
        # Show completion message
        messagebox.showinfo("Analysis Complete", 
                          "Log analysis completed successfully!")
    
    def update_summary_tab(self):
        """Update the summary tab with analysis results."""
        summary_report = self.analyzer.generate_summary_report()
        
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(tk.END, summary_report)
        self.summary_text.config(state=tk.DISABLED)
    
    def update_ip_tab(self):
        """Update the IP analysis tab."""
        ip_data = self.current_results.get('ip_addresses', {})
        
        # Clear existing data
        for item in self.ip_tree.get_children():
            self.ip_tree.delete(item)
        
        # Add IP data
        for ip, count in ip_data.get('top_ips', []):
            ip_type = "Internal" if ip in ip_data.get('internal_ips', []) else "External"
            status = "Suspicious" if ip in ip_data.get('suspicious_ips', []) else "Normal"
            
            self.ip_tree.insert('', 'end', values=(ip, count, ip_type, status))
    
    def update_security_tab(self):
        """Update the security analysis tab."""
        security_data = self.current_results.get('security_analysis', {})
        
        # Update security alerts
        self.security_text.config(state=tk.NORMAL)
        self.security_text.delete(1.0, tk.END)
        
        alerts = security_data.get('security_alerts', [])
        if alerts:
            for alert in alerts:
                self.security_text.insert(tk.END, f"⚠️ {alert}\n")
        else:
            self.security_text.insert(tk.END, "No security alerts detected.")
        
        self.security_text.config(state=tk.DISABLED)
        
        # Update security metrics
        for item in self.metrics_tree.get_children():
            self.metrics_tree.delete(item)
        
        metrics = [
            ("SQL Injection Attempts", security_data.get('sql_injection_attempts', 0)),
            ("XSS Attempts", security_data.get('xss_attempts', 0)),
            ("Login-related Entries", security_data.get('login_related_entries', 0))
        ]
        
        for metric, value in metrics:
            self.metrics_tree.insert('', 'end', values=(metric, value))
    
    def update_traffic_tab(self):
        """Update the traffic analysis tab."""
        status_data = self.current_results.get('status_codes', {})
        urls_data = self.current_results.get('urls', {})
        
        # Update status codes
        for item in self.status_tree.get_children():
            self.status_tree.delete(item)
        
        total_responses = status_data.get('total_responses', 0)
        for status, count in status_data.get('top_status_codes', []):
            percentage = (count / total_responses * 100) if total_responses > 0 else 0
            self.status_tree.insert('', 'end', 
                                  values=(status, count, f"{percentage:.1f}%"))
        
        # Update top URLs
        for item in self.urls_tree.get_children():
            self.urls_tree.delete(item)
        
        for url, count in urls_data.get('top_endpoints', []):
            self.urls_tree.insert('', 'end', values=(url, count))
    
    def update_raw_data_tab(self):
        """Update the raw data tab."""
        self.raw_text.config(state=tk.NORMAL)
        self.raw_text.delete(1.0, tk.END)
        
        # Pretty print JSON
        json_str = json.dumps(self.current_results, indent=2, default=str)
        self.raw_text.insert(tk.END, json_str)
        
        self.raw_text.config(state=tk.DISABLED)
    
    def export_report(self):
        """Export analysis report to text file."""
        if not self.current_results:
            messagebox.showerror("Error", "No analysis results to export.")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save Report As",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                report = self.analyzer.generate_summary_report()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                messagebox.showinfo("Success", f"Report exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")
    
    def export_json(self):
        """Export analysis results to JSON file."""
        if not self.current_results:
            messagebox.showerror("Error", "No analysis results to export.")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save JSON As",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.current_results, f, indent=2, default=str)
                messagebox.showinfo("Success", f"Data exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export JSON: {str(e)}")
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()
