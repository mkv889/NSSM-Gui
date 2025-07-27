import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTableWidget, QVBoxLayout, QWidget, QMessageBox

class NSSMGui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NSSM Service Manager")
        self.setGeometry(100, 100, 800, 600)
        self.initUI()

    def initUI(self):
        self.table = QTableWidget(self)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Service Name", "Display Name", "Status", "Application Path"])
        self.load_services()
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.open_context_menu)
    def open_context_menu(self, pos):
        from PyQt5.QtWidgets import QMenu
        menu = QMenu(self)
        start_action = menu.addAction("Start Service")
        stop_action = menu.addAction("Stop Service")
        restart_action = menu.addAction("Restart Service")
        remove_action = menu.addAction("Remove Service")
        edit_action = menu.addAction("Edit Service")
        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        row = self.table.currentRow()
        if row < 0:
            return
        svc_name = self.table.item(row, 0).text()
        if action == start_action:
            self.service_command('start', svc_name)
        elif action == stop_action:
            self.service_command('stop', svc_name)
        elif action == restart_action:
            self.service_command('restart', svc_name)
        elif action == remove_action:
            self.remove_service(svc_name)
        elif action == edit_action:
            self.edit_service(svc_name)

    def service_command(self, cmd, svc_name):
        try:
            result = subprocess.run(['nssm.exe', cmd, svc_name], capture_output=True, text=True)
            if result.returncode == 0:
                QMessageBox.information(self, "Success", f"Service '{svc_name}' {cmd}ed successfully!")
            else:
                QMessageBox.critical(self, "Error", result.stderr)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
        self.load_services()

    def remove_service(self, svc_name):
        from PyQt5.QtWidgets import QMessageBox
        reply = QMessageBox.question(self, 'Remove Service', f"Are you sure you want to remove '{svc_name}'?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.service_command('remove', svc_name)

    def edit_service(self, svc_name):
        from PyQt5.QtWidgets import (QDialog, QTabWidget, QWidget, QFormLayout, QLineEdit, QPushButton, QFileDialog, QHBoxLayout, QVBoxLayout, QComboBox, QTextEdit, QCheckBox, QLabel, QMessageBox)
        import subprocess
        def nssm_get(param):
            try:
                result = subprocess.run(['nssm.exe', 'get', svc_name, param], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.strip()
            except Exception:
                pass
            return ''

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit Service: {svc_name}")
        layout = QVBoxLayout(dialog)
        tabs = QTabWidget(dialog)

        # --- Application Tab ---
        app_tab = QWidget()
        app_form = QFormLayout(app_tab)
        exe_edit = QLineEdit(nssm_get('Application'), app_tab)
        args_edit = QLineEdit(nssm_get('AppParameters'), app_tab)
        dir_edit = QLineEdit(nssm_get('AppDirectory'), app_tab)
        env_edit = QTextEdit(app_tab)
        env_val = nssm_get('AppEnvironmentExtra')
        env_edit.setPlainText(env_val.replace(' ', '\n') if env_val else '')
        console_chk = QCheckBox("Show Console Window", app_tab)
        console_chk.setChecked(nssm_get('Console') == '1')
        priority_combo = QComboBox(app_tab)
        priority_combo.addItems(["Normal", "High", "Idle", "RealTime", "BelowNormal", "AboveNormal"])
        prio_val = nssm_get('Priority')
        if prio_val:
            idx = priority_combo.findText(prio_val)
            if idx >= 0:
                priority_combo.setCurrentIndex(idx)
        affinity_edit = QLineEdit(nssm_get('Affinity'), app_tab)
        exe_browse_btn = QPushButton("Browse", app_tab)
        def browse_exe():
            path, _ = QFileDialog.getOpenFileName(dialog, "Select Executable", "", "Executables (*.exe);;All Files (*)")
            if path:
                exe_edit.setText(path)
        exe_browse_btn.clicked.connect(browse_exe)
        exe_layout = QHBoxLayout()
        exe_layout.addWidget(exe_edit)
        exe_layout.addWidget(exe_browse_btn)
        app_form.addRow("Executable Path:", exe_layout)
        app_form.addRow("Arguments:", args_edit)
        app_form.addRow("Startup Directory:", dir_edit)
        app_form.addRow("Environment Variables (key=value per line):", env_edit)
        app_form.addRow(console_chk)
        app_form.addRow("Process Priority:", priority_combo)
        app_form.addRow("CPU Affinity (comma-separated cores):", affinity_edit)
        app_tab.setLayout(app_form)

        # --- Details Tab ---
        details_tab = QWidget()
        details_form = QFormLayout(details_tab)
        display_name_edit = QLineEdit(nssm_get('DisplayName'), details_tab)
        desc_edit = QLineEdit(nssm_get('Description'), details_tab)
        startup_combo = QComboBox(details_tab)
        startup_combo.addItems(["Automatic", "Delayed", "Manual", "Disabled"])
        startup_map = {"SERVICE_AUTO_START": "Automatic", "SERVICE_DELAYED_AUTO_START": "Delayed", "SERVICE_DEMAND_START": "Manual", "SERVICE_DISABLED": "Disabled"}
        start_val = nssm_get('Start')
        if start_val:
            idx = startup_combo.findText(startup_map.get(start_val, "Automatic"))
            if idx >= 0:
                startup_combo.setCurrentIndex(idx)
        details_form.addRow("Display Name:", display_name_edit)
        details_form.addRow("Description:", desc_edit)
        details_form.addRow("Startup Type:", startup_combo)
        details_tab.setLayout(details_form)

        # --- Log On Tab ---
        logon_tab = QWidget()
        logon_form = QFormLayout(logon_tab)
        account_edit = QLineEdit(nssm_get('ObjectName'), logon_tab)
        password_edit = QLineEdit('', logon_tab)
        password_edit.setEchoMode(QLineEdit.Password)
        interact_chk = QCheckBox("Allow service to interact with desktop", logon_tab)
        interact_chk.setChecked(nssm_get('Type') == 'SERVICE_INTERACTIVE_PROCESS')
        logon_form.addRow("Account (blank for LocalSystem):", account_edit)
        logon_form.addRow("Password:", password_edit)
        logon_form.addRow(interact_chk)
        logon_tab.setLayout(logon_form)

        # --- Dependencies Tab ---
        dep_tab = QWidget()
        dep_form = QFormLayout(dep_tab)
        dep_edit = QLineEdit(nssm_get('DependOnService'), dep_tab)
        dep_form.addRow("Dependencies (comma-separated):", dep_edit)
        dep_tab.setLayout(dep_form)

        # --- Shutdown Tab ---
        shutdown_tab = QWidget()
        shutdown_form = QFormLayout(shutdown_tab)
        method_combo = QComboBox(shutdown_tab)
        method_combo.addItems(["Control-C", "WM_CLOSE", "WM_QUIT", "Terminate" ])
        method_val = nssm_get('KillConsoleApp')
        if method_val:
            idx = method_combo.findText(method_val)
            if idx >= 0:
                method_combo.setCurrentIndex(idx)
        timeout_edit = QLineEdit(nssm_get('KillProcessTimeout'), shutdown_tab)
        shutdown_form.addRow("Shutdown Method:", method_combo)
        shutdown_form.addRow("Shutdown Timeout (ms):", timeout_edit)
        shutdown_tab.setLayout(shutdown_form)

        # --- Exit Actions Tab ---
        exit_tab = QWidget()
        exit_form = QFormLayout(exit_tab)
        restart_combo = QComboBox(exit_tab)
        restart_combo.addItems(["Restart", "Ignore", "Exit"])
        exit_val = nssm_get('AppExit')
        if exit_val:
            idx = restart_combo.findText(exit_val)
            if idx >= 0:
                restart_combo.setCurrentIndex(idx)
        delay_edit = QLineEdit(nssm_get('AppRestartDelay'), exit_tab)
        throttle_edit = QLineEdit(nssm_get('Throttle'), exit_tab)
        exit_form.addRow("On Exit Action:", restart_combo)
        exit_form.addRow("Restart Delay (ms):", delay_edit)
        exit_form.addRow("Restart Throttling (ms):", throttle_edit)
        exit_tab.setLayout(exit_form)

        # --- I/O Tab ---
        io_tab = QWidget()
        io_form = QFormLayout(io_tab)
        stdin_edit = QLineEdit(nssm_get('AppStdin'), io_tab)
        stdout_edit = QLineEdit(nssm_get('AppStdout'), io_tab)
        stderr_edit = QLineEdit(nssm_get('AppStderr'), io_tab)
        rotation_chk = QCheckBox("Enable File Rotation", io_tab)
        rotation_chk.setChecked(nssm_get('RotateFiles') == '1')
        rotation_size_edit = QLineEdit(nssm_get('RotateBytes'), io_tab)
        rotation_time_edit = QLineEdit(nssm_get('RotateSeconds'), io_tab)
        io_form.addRow("Standard Input File:", stdin_edit)
        io_form.addRow("Standard Output File:", stdout_edit)
        io_form.addRow("Standard Error File:", stderr_edit)
        io_form.addRow(rotation_chk)
        io_form.addRow("Rotation Size (bytes):", rotation_size_edit)
        io_form.addRow("Rotation Time (seconds):", rotation_time_edit)
        io_tab.setLayout(io_form)

        tabs.addTab(app_tab, "Application")
        tabs.addTab(details_tab, "Details")
        tabs.addTab(logon_tab, "Log On")
        tabs.addTab(dep_tab, "Dependencies")
        tabs.addTab(shutdown_tab, "Shutdown")
        tabs.addTab(exit_tab, "Exit Actions")
        tabs.addTab(io_tab, "I/O")

        layout.addWidget(tabs)

        btn_box = QHBoxLayout()
        ok_btn = QPushButton("Save", dialog)
        cancel_btn = QPushButton("Cancel", dialog)
        btn_box.addWidget(ok_btn)
        btn_box.addWidget(cancel_btn)
        layout.addLayout(btn_box)

        def do_save():
            exe_new = exe_edit.text().strip()
            args_new = args_edit.text().strip()
            if not exe_new:
                QMessageBox.warning(dialog, "Input Error", "Executable path is required.")
                return
            try:
                def nssm_set(param, value):
                    if value is not None:
                        subprocess.run(['nssm.exe', 'set', svc_name, param, value], capture_output=True, text=True)
                nssm_set('Application', exe_new)
                nssm_set('AppParameters', args_new)
                nssm_set('AppDirectory', dir_edit.text().strip())
                # Environment
                env_lines = [l.strip() for l in env_edit.toPlainText().splitlines() if l.strip()]
                if env_lines:
                    nssm_set('AppEnvironmentExtra', ' '.join(env_lines))
                nssm_set('Console', '1' if console_chk.isChecked() else '0')
                nssm_set('Priority', priority_combo.currentText())
                nssm_set('Affinity', affinity_edit.text().strip())
                nssm_set('DisplayName', display_name_edit.text().strip())
                nssm_set('Description', desc_edit.text().strip())
                # Startup type
                startup_map = {"Automatic": "SERVICE_AUTO_START", "Delayed": "SERVICE_DELAYED_AUTO_START", "Manual": "SERVICE_DEMAND_START", "Disabled": "SERVICE_DISABLED"}
                nssm_set('Start', startup_map.get(startup_combo.currentText(), 'SERVICE_AUTO_START'))
                # Logon
                nssm_set('ObjectName', account_edit.text().strip())
                nssm_set('Password', password_edit.text().strip())
                nssm_set('Type', 'SERVICE_INTERACTIVE_PROCESS' if interact_chk.isChecked() else '')
                # Dependencies
                nssm_set('DependOnService', dep_edit.text().strip())
                # Shutdown
                nssm_set('KillConsoleApp', method_combo.currentText())
                nssm_set('KillProcessTimeout', timeout_edit.text().strip())
                # Exit actions
                nssm_set('AppExit', restart_combo.currentText())
                nssm_set('AppRestartDelay', delay_edit.text().strip())
                nssm_set('Throttle', throttle_edit.text().strip())
                # I/O
                nssm_set('AppStdin', stdin_edit.text().strip())
                nssm_set('AppStdout', stdout_edit.text().strip())
                nssm_set('AppStderr', stderr_edit.text().strip())
                nssm_set('RotateFiles', '1' if rotation_chk.isChecked() else '0')
                nssm_set('RotateBytes', rotation_size_edit.text().strip())
                nssm_set('RotateSeconds', rotation_time_edit.text().strip())
                QMessageBox.information(dialog, "Success", f"Service '{svc_name}' updated successfully!")
                dialog.accept()
                self.load_services()
            except Exception as e:
                QMessageBox.critical(dialog, "Error", str(e))

        ok_btn.clicked.connect(do_save)
        cancel_btn.clicked.connect(dialog.reject)
        dialog.exec_()

        self.install_btn = QPushButton("Install Service", self)
        self.install_btn.clicked.connect(self.install_service)

        layout = QVBoxLayout()
        layout.addWidget(self.table)
        layout.addWidget(self.install_btn)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def load_services(self):
        import winreg
        import re
        from PyQt5.QtCore import Qt

        # Get list of all services
        result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], capture_output=True, text=True)
        services = re.findall(r'SERVICE_NAME: (.+)', result.stdout)
        service_info = []
        for svc in services:
            # Get display name and status
            disp = svc
            status = "Unknown"
            match = re.search(rf'SERVICE_NAME: {re.escape(svc)}\s+DISPLAY_NAME: (.+?)\s+\n', result.stdout)
            if match:
                disp = match.group(1)
            match2 = re.search(rf'SERVICE_NAME: {re.escape(svc)}[\s\S]+?STATE +: +\d+ +([A-Z_]+)', result.stdout)
            if match2:
                status = match2.group(1)
            # Get ImagePath from registry
            try:
                reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, fr'SYSTEM\\CurrentControlSet\\Services\\{svc}')
                img_path, _ = winreg.QueryValueEx(reg, 'ImagePath')
                winreg.CloseKey(reg)
            except Exception:
                img_path = ''
            # Heuristic: NSSM-managed if path contains 'nssm' or 'nssm.exe'
            if 'nssm' in img_path.lower():
                service_info.append((svc, disp, status, img_path))
        self.table.setRowCount(len(service_info))
        for row, (svc, disp, status, img_path) in enumerate(service_info):
            self.table.setItem(row, 0, self._readonly_item(svc))
            self.table.setItem(row, 1, self._readonly_item(disp))
            self.table.setItem(row, 2, self._readonly_item(status))
            self.table.setItem(row, 3, self._readonly_item(img_path))
        self.table.resizeColumnsToContents()

    def _readonly_item(self, text):
        from PyQt5.QtWidgets import QTableWidgetItem
        item = QTableWidgetItem(text)
        item.setFlags(item.flags() ^ Qt.ItemIsEditable)
        return item

    def install_service(self):
        from PyQt5.QtWidgets import (QDialog, QTabWidget, QWidget, QFormLayout, QLineEdit, QPushButton, QFileDialog, QHBoxLayout, QVBoxLayout, QComboBox, QTextEdit, QCheckBox, QLabel, QMessageBox)
        dialog = QDialog(self)
        dialog.setWindowTitle("Install New Service")
        layout = QVBoxLayout(dialog)

        tabs = QTabWidget(dialog)

        # --- Application Tab ---
        app_tab = QWidget()
        app_form = QFormLayout(app_tab)
        name_edit = QLineEdit(app_tab)
        exe_edit = QLineEdit(app_tab)
        args_edit = QLineEdit(app_tab)
        dir_edit = QLineEdit(app_tab)
        env_edit = QTextEdit(app_tab)
        console_chk = QCheckBox("Show Console Window", app_tab)
        priority_combo = QComboBox(app_tab)
        priority_combo.addItems(["Normal", "High", "Idle", "RealTime", "BelowNormal", "AboveNormal"])
        affinity_edit = QLineEdit(app_tab)
        exe_browse_btn = QPushButton("Browse", app_tab)
        def browse_exe():
            path, _ = QFileDialog.getOpenFileName(dialog, "Select Executable", "", "Executables (*.exe);;All Files (*)")
            if path:
                exe_edit.setText(path)
        exe_browse_btn.clicked.connect(browse_exe)
        exe_layout = QHBoxLayout()
        exe_layout.addWidget(exe_edit)
        exe_layout.addWidget(exe_browse_btn)
        app_form.addRow("Service Name:", name_edit)
        app_form.addRow("Executable Path:", exe_layout)
        app_form.addRow("Arguments:", args_edit)
        app_form.addRow("Startup Directory:", dir_edit)
        app_form.addRow("Environment Variables (key=value per line):", env_edit)
        app_form.addRow(console_chk)
        app_form.addRow("Process Priority:", priority_combo)
        app_form.addRow("CPU Affinity (comma-separated cores):", affinity_edit)
        app_tab.setLayout(app_form)

        # --- Details Tab ---
        details_tab = QWidget()
        details_form = QFormLayout(details_tab)
        display_name_edit = QLineEdit(details_tab)
        desc_edit = QLineEdit(details_tab)
        startup_combo = QComboBox(details_tab)
        startup_combo.addItems(["Automatic", "Delayed", "Manual", "Disabled"])
        details_form.addRow("Display Name:", display_name_edit)
        details_form.addRow("Description:", desc_edit)
        details_form.addRow("Startup Type:", startup_combo)
        details_tab.setLayout(details_form)

        # --- Log On Tab ---
        logon_tab = QWidget()
        logon_form = QFormLayout(logon_tab)
        account_edit = QLineEdit(logon_tab)
        password_edit = QLineEdit(logon_tab)
        password_edit.setEchoMode(QLineEdit.Password)
        interact_chk = QCheckBox("Allow service to interact with desktop", logon_tab)
        logon_form.addRow("Account (blank for LocalSystem):", account_edit)
        logon_form.addRow("Password:", password_edit)
        logon_form.addRow(interact_chk)
        logon_tab.setLayout(logon_form)

        # --- Dependencies Tab ---
        dep_tab = QWidget()
        dep_form = QFormLayout(dep_tab)
        dep_edit = QLineEdit(dep_tab)
        dep_form.addRow("Dependencies (comma-separated):", dep_edit)
        dep_tab.setLayout(dep_form)

        # --- Shutdown Tab ---
        shutdown_tab = QWidget()
        shutdown_form = QFormLayout(shutdown_tab)
        method_combo = QComboBox(shutdown_tab)
        method_combo.addItems(["Control-C", "WM_CLOSE", "WM_QUIT", "Terminate" ])
        timeout_edit = QLineEdit(shutdown_tab)
        shutdown_form.addRow("Shutdown Method:", method_combo)
        shutdown_form.addRow("Shutdown Timeout (ms):", timeout_edit)
        shutdown_tab.setLayout(shutdown_form)

        # --- Exit Actions Tab ---
        exit_tab = QWidget()
        exit_form = QFormLayout(exit_tab)
        restart_combo = QComboBox(exit_tab)
        restart_combo.addItems(["Restart", "Ignore", "Exit"])
        delay_edit = QLineEdit(exit_tab)
        throttle_edit = QLineEdit(exit_tab)
        exit_form.addRow("On Exit Action:", restart_combo)
        exit_form.addRow("Restart Delay (ms):", delay_edit)
        exit_form.addRow("Restart Throttling (ms):", throttle_edit)
        exit_tab.setLayout(exit_form)

        # --- I/O Tab ---
        io_tab = QWidget()
        io_form = QFormLayout(io_tab)
        stdin_edit = QLineEdit(io_tab)
        stdout_edit = QLineEdit(io_tab)
        stderr_edit = QLineEdit(io_tab)
        rotation_chk = QCheckBox("Enable File Rotation", io_tab)
        rotation_size_edit = QLineEdit(io_tab)
        rotation_time_edit = QLineEdit(io_tab)
        io_form.addRow("Standard Input File:", stdin_edit)
        io_form.addRow("Standard Output File:", stdout_edit)
        io_form.addRow("Standard Error File:", stderr_edit)
        io_form.addRow(rotation_chk)
        io_form.addRow("Rotation Size (bytes):", rotation_size_edit)
        io_form.addRow("Rotation Time (seconds):", rotation_time_edit)
        io_tab.setLayout(io_form)

        tabs.addTab(app_tab, "Application")
        tabs.addTab(details_tab, "Details")
        tabs.addTab(logon_tab, "Log On")
        tabs.addTab(dep_tab, "Dependencies")
        tabs.addTab(shutdown_tab, "Shutdown")
        tabs.addTab(exit_tab, "Exit Actions")
        tabs.addTab(io_tab, "I/O")

        layout.addWidget(tabs)

        btn_box = QHBoxLayout()
        ok_btn = QPushButton("Install", dialog)
        cancel_btn = QPushButton("Cancel", dialog)
        btn_box.addWidget(ok_btn)
        btn_box.addWidget(cancel_btn)
        layout.addLayout(btn_box)

        def do_install():
            name = name_edit.text().strip()
            exe = exe_edit.text().strip()
            args = args_edit.text().strip()
            if not name or not exe:
                QMessageBox.warning(dialog, "Input Error", "Service name and executable path are required.")
                return
            cmd = ['nssm.exe', 'install', name, exe]
            if args:
                cmd.append(args)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    QMessageBox.critical(dialog, "Error", result.stderr)
                    return
                # Set all other options using nssm set
                def nssm_set(param, value):
                    if value:
                        subprocess.run(['nssm.exe', 'set', name, param, value], capture_output=True, text=True)
                nssm_set('AppDirectory', dir_edit.text().strip())
                nssm_set('AppParameters', args_edit.text().strip())
                # Environment
                env_lines = [l.strip() for l in env_edit.toPlainText().splitlines() if l.strip()]
                if env_lines:
                    nssm_set('AppEnvironmentExtra', ' '.join(env_lines))
                nssm_set('Console', '1' if console_chk.isChecked() else '0')
                nssm_set('Priority', priority_combo.currentText())
                nssm_set('Affinity', affinity_edit.text().strip())
                nssm_set('DisplayName', display_name_edit.text().strip())
                nssm_set('Description', desc_edit.text().strip())
                # Startup type
                startup_map = {"Automatic": "SERVICE_AUTO_START", "Delayed": "SERVICE_DELAYED_AUTO_START", "Manual": "SERVICE_DEMAND_START", "Disabled": "SERVICE_DISABLED"}
                nssm_set('Start', startup_map.get(startup_combo.currentText(), 'SERVICE_AUTO_START'))
                # Logon
                nssm_set('ObjectName', account_edit.text().strip())
                nssm_set('Password', password_edit.text().strip())
                nssm_set('Type', 'SERVICE_INTERACTIVE_PROCESS' if interact_chk.isChecked() else '')
                # Dependencies
                nssm_set('DependOnService', dep_edit.text().strip())
                # Shutdown
                nssm_set('KillConsoleApp', method_combo.currentText())
                nssm_set('KillProcessTimeout', timeout_edit.text().strip())
                # Exit actions
                nssm_set('AppExit', restart_combo.currentText())
                nssm_set('AppRestartDelay', delay_edit.text().strip())
                nssm_set('Throttle', throttle_edit.text().strip())
                # I/O
                nssm_set('AppStdin', stdin_edit.text().strip())
                nssm_set('AppStdout', stdout_edit.text().strip())
                nssm_set('AppStderr', stderr_edit.text().strip())
                nssm_set('RotateFiles', '1' if rotation_chk.isChecked() else '0')
                nssm_set('RotateBytes', rotation_size_edit.text().strip())
                nssm_set('RotateSeconds', rotation_time_edit.text().strip())
                QMessageBox.information(dialog, "Success", f"Service '{name}' installed successfully!")
                dialog.accept()
                self.load_services()
            except Exception as e:
                QMessageBox.critical(dialog, "Error", str(e))

        ok_btn.clicked.connect(do_install)
        cancel_btn.clicked.connect(dialog.reject)
        dialog.exec_()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NSSMGui()
    window.show()
    sys.exit(app.exec_())
