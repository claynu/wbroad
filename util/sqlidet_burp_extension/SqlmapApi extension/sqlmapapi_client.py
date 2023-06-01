# coding:utf-8
import array

from burp import IBurpExtender
from burp import IMenuItemHandler
from burp import IContextMenuFactory
from javax.swing.table import AbstractTableModel, DefaultTableModel, DefaultTableCellRenderer
from burp import IMessageEditorController
from javax.swing import KeyStroke
import base64
from burp import ITab, IMessageEditor
from burp import IExtensionStateListener
from javax import swing
from java.awt import Font
from java.awt import Color
from java import awt
from java.lang import Process
import urllib2
import json
from java.util import List
import traceback
from java.awt import Color
from java.awt.event import InputEvent, KeyEvent, MouseAdapter, ComponentAdapter
import os

config_file = 'sql_api_config.ini'
default_config = {
    'host': '127.0.0.1',
    'port': '6000',
    'user': 'heyu',
    'project': 'test_v1.2',
    'options': {"level": 3, "risk": 3, "threads": 5}
}
data = {}
if not os.path.isfile(config_file):
    config = open(config_file, 'a')
    config.write(json.dumps(default_config))
    config.close()
    data = default_config
else:
    config = open(config_file, 'r')
    data = config.read()
    data = json.loads(data)

host = data.get('host', '127.0.0.1')
port = data.get('port', '8557')
username = data.get('user', 'customer')
project = data.get('project', 'test')
options = data.get('options', {"level": 3, "risk": 3, "threads": 5})


class CustomTableCellRenderer(DefaultTableCellRenderer):
    def __init__(self):
        super(DefaultTableCellRenderer, self).__init__()
        self.button = swing.JButton('Remove')

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        if column == table.getColumnCount() - 1:
            return self.button
        super(CustomTableCellRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row,
                                                                           column)
        if isinstance(value, list) and len(value) > 0:
            last_value = value[-2]
            if last_value > 0:
                self.setForeground(Color.RED)
            else:
                self.setForeground(Color.BLACK)
            return self
        else:
            return


class ButtonEditor(swing.DefaultCellEditor):
    def __init__(self):
        super(ButtonEditor, self).__init__(swing.JCheckBox())
        self.button = swing.JButton('Remove')
        swing.JButton('Remove').addActionListener(self)

    def actionPerformed(self, event):
        print('remove button clicked')
        print(event)

    def getTableCellEditorComponent(self, table, value, isSelected, row, column):
        if column == table.getColumnCount() - 1:
            return self.button
        else:
            return super(ButtonEditor, self).getTableCellEditorComponent(table, value, isSelected, row, column)


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener, IMenuItemHandler,
                   IMessageEditorController, ComponentAdapter):
    scantasks = []

    def registerExtenderCallbacks(self, callbacks):
        global messageEditor, messageLogEditor, username, project
        messageEditor = callbacks.createMessageEditor(None, True)
        messageLogEditor = callbacks.createMessageEditor(None, True)
        self.printHeader()
        callbacks.setExtensionName("SqlMapApi Client")
        callbacks.registerExtensionStateListener(self)

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerContextMenuFactory(self)

        # Create SQLMap API configuration JPanel
        self._jPanel = swing.JPanel()
        self._jPanel.setLayout(awt.GridBagLayout())
        self._jPanelConstraints = awt.GridBagConstraints()

        # Create first blank space
        self._jLabelAPISpace1 = swing.JLabel(" ")
        self._jLabelAPISpace1.setFont(Font("Courier New", Font.BOLD, 30))
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 2
        self._jPanelConstraints.gridwidth = 2
        self._jPanel.add(self._jLabelAPISpace1, self._jPanelConstraints)

        # Create second blank space
        self._jLabelAPISpace2 = swing.JLabel(" ")
        self._jLabelAPISpace2.setFont(Font("Courier New", Font.BOLD, 30))
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 3
        self._jPanelConstraints.gridwidth = 2
        self._jPanel.add(self._jLabelAPISpace2, self._jPanelConstraints)

        # Create panel to show API status
        self._jLabelAPIStatus = swing.JLabel("SQLMap API is NOT running!")
        self._jLabelAPIStatus.setFont(Font("Courier New", Font.BOLD, 24))
        self._jLabelAPIStatus.setForeground(Color.RED)
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 4
        self._jPanelConstraints.gridwidth = 2
        self._jPanel.add(self._jLabelAPIStatus, self._jPanelConstraints)

        # Create third blank space
        self._jLabelAPISpace3 = swing.JLabel(" ")
        self._jLabelAPISpace3.setFont(Font("Courier New", Font.BOLD, 30))
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 5
        self._jPanelConstraints.gridwidth = 2
        self._jPanel.add(self._jLabelAPISpace3, self._jPanelConstraints)

        # Create panel for IP info
        self._jLabelIPListen = swing.JLabel("Listen on IP:")
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 6
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jLabelIPListen, self._jPanelConstraints)

        self._jTextFieldIPListen = swing.JTextField(host, 15)
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 6
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jTextFieldIPListen, self._jPanelConstraints)

        # Create panel for Port info
        self._jLabelPortListen = swing.JLabel("Listen on Port:")
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 7
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jLabelPortListen, self._jPanelConstraints)

        self._jTextFieldPortListen = swing.JTextField(port, 3)
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 7
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jTextFieldPortListen, self._jPanelConstraints)

        # Create panel for Port info
        self._jLabelUser = swing.JLabel("User:")
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 8
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jLabelUser, self._jPanelConstraints)

        self._jTextFieldUser = swing.JTextField(username, 3)
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 8
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jTextFieldUser, self._jPanelConstraints)

        # Create panel for Port info
        self._jLabelProject = swing.JLabel("project:")
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 9
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jLabelProject, self._jPanelConstraints)

        self._jTextFieldProject = swing.JTextField(project, 3)
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 9
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jTextFieldProject, self._jPanelConstraints)

        # Create panel to execute API
        self._jButtonStartAPI = swing.JButton('Check Server', actionPerformed=self.startAPI)

        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 10
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jButtonStartAPI, self._jPanelConstraints)

        self._jButtonStartAPI = swing.JButton('Save Config', actionPerformed=self.saveConfig)
        self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 10
        self._jPanelConstraints.gridwidth = 1
        self._jPanel.add(self._jButtonStartAPI, self._jPanelConstraints)

        # GUI components
        self._jLabelScanText = swing.JLabel()
        self._jLabelScanIPListen = swing.JLabel()
        self._jLabelScanPortListen = swing.JLabel()
        self._jTextFieldScanIPListen = swing.JTextField()
        self._jTextFieldScanPortListen = swing.JTextField()

        self._jLabelURL = swing.JLabel()
        self._jTextFieldURL = swing.JTextField()
        self._jLabelData = swing.JLabel()
        self._jTextData = swing.JTextArea()
        self._jScrollPaneData = swing.JScrollPane(self._jTextData)
        self._jLabelOptions = swing.JLabel()
        self._jTextOptions = swing.JTextArea()
        self._jScrollPaneOtion = swing.JScrollPane(self._jTextOptions)

        self._jButtonStartScan = swing.JButton('Start Scan', actionPerformed=self.startScan)

        self._jLabelScanAPI = swing.JLabel()
        self._jLabelScanAPI.setText('SQLMap API is NOT running!')
        self._jLabelScanAPI.setForeground(Color.RED)

        # Configure GUI
        self._jLabelScanText.setText('API Listening On:')
        self._jLabelScanIPListen.setText('SQLMap API IP:')
        self._jLabelScanPortListen.setText('SQLMap API Port:')
        self._jLabelURL.setText('URL:')
        self._jLabelData.setText('Post Data:')
        self._jTextData.setLineWrap(True)
        self._jTextOptions.setLineWrap(True)
        self._jTextOptions.setText(json.dumps(options))
        self._jScrollPaneData.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jScrollPaneOtion.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jLabelOptions.setText('Options:')

        # Configure locations
        self._jLabelScanText.setBounds(15, 16, 126, 20)
        self._jLabelScanIPListen.setBounds(15, 58, 115, 20)

        self._jLabelScanPortListen.setBounds(402, 55, 129, 20)
        self._jTextFieldScanIPListen.setBounds(167, 52, 206, 26)

        self._jTextFieldScanPortListen.setBounds(546, 52, 63, 26)

        self._jLabelURL.setBounds(15, 103, 35, 20)
        self._jTextFieldURL.setBounds(166, 100, 535, 26)

        self._jLabelData.setBounds(15, 143, 73, 20)
        self._jScrollPaneData.setBounds(166, 140, 535, 146)

        self._jLabelOptions.setBounds(15, 303, 61, 20)
        self._jScrollPaneOtion.setBounds(166, 300, 535, 96)

        self._jButtonStartScan.setBounds(346, 403, 103, 29)
        self._jLabelScanAPI.setBounds(167, 16, 275, 20)

        # Create main panel
        self._jScanPanel = swing.JPanel()
        self._jScanPanel.setLayout(None)
        self._jScanPanel.setPreferredSize(awt.Dimension(1368, 1368))
        self._jScanPanel.add(self._jLabelScanText)
        self._jScanPanel.add(self._jLabelScanIPListen)
        self._jScanPanel.add(self._jLabelScanPortListen)
        self._jScanPanel.add(self._jTextFieldScanIPListen)
        self._jScanPanel.add(self._jTextFieldScanPortListen)

        self._jScanPanel.add(self._jLabelURL)
        self._jScanPanel.add(self._jTextFieldURL)
        self._jScanPanel.add(self._jLabelData)
        self._jScanPanel.add(self._jScrollPaneData)
        self._jScanPanel.add(self._jLabelOptions)
        self._jScanPanel.add(self._jScrollPaneOtion)

        self._jScanPanel.add(self._jButtonStartScan)
        self._jScanPanel.add(self._jLabelScanAPI)
        self._jScrollPaneMain = swing.JScrollPane(self._jScanPanel)
        self._jScrollPaneMain.setViewportView(self._jScanPanel)
        self._jScrollPaneMain.setPreferredSize(awt.Dimension(1357, 1357))

        # Create SQLMap stop scan JPanel
        self._jStopScanPanel = swing.JPanel()
        self._jStopScanPanel.setLayout(None)

        # Create label, combobox, and button to stop scans and textfield to display success
        self._jLabelStopScan = swing.JLabel("Stop Scan ID:")
        self._jComboStopScan = swing.JComboBox(self.scantasks)
        self._jButtonStopScan = swing.JButton('delete', actionPerformed=self.stopScan)
        self._jButtonRemoveScan = swing.JButton('Remove', actionPerformed=self.removeScan)
        self._jLabelStopStatus = swing.JLabel()

        self._jLabelStopScan.setBounds(15, 16, 126, 20)
        self._jComboStopScan.setBounds(167, 16, 535, 20)
        self._jButtonStopScan.setBounds(718, 16, 80, 20)
        self._jButtonRemoveScan.setBounds(810, 16, 80, 20)
        self._jLabelStopStatus.setBounds(167, 58, 846, 20)

        self._jStopScanPanel.add(self._jLabelStopScan)
        self._jStopScanPanel.add(self._jComboStopScan)
        self._jStopScanPanel.add(self._jButtonStopScan)
        self._jStopScanPanel.add(self._jButtonRemoveScan)
        self._jStopScanPanel.add(self._jLabelStopStatus)

        # reuslt table panel

        self._jResultPanel = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)

        # table
        self._jResultTablePanel = swing.JPanel()
        self._jResultTablePanel.setLayout(None)
        self._model = DefaultTableModel(["taskId", "status", "host", "uri", "result"], 5)
        self._resTable = swing.JTable(self._model)
        self._resTable.setFillsViewportHeight(True)
        self._resTable.addMouseListener(myTableListener(self._resTable, host=str(self._jTextFieldIPListen.getText()),
                                                        port=str(self._jTextFieldPortListen.getText())))
        # self._resTable.setDefaultRenderer(List, CustomTableCellRenderer())
        # self._resTable.getColumn(self._resTable.getColumnCount()-1).setCellRenderer(CustomTableCellRenderer())
        # self._resTable.getColumn(self._resTable.getColumnCount()-1).setCellEditor(ButtonEditor())

        self._resTable.setAutoResizeMode(swing.JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._scrollPane = swing.JScrollPane(self._resTable)

        # Create label, combobox, and button to stop scans and textfield to display success
        self._jLabelResultScan = swing.JLabel("Results: ")

        self._jButtonResRefresh = swing.JButton('Refresh', actionPerformed=self.getResults)
        self._jButtonRemoveScan = swing.JButton('Clean', actionPerformed=self.cleanResults)

        print(self._jResultTablePanel.getWidth())
        self._jLabelResultScan.setBounds(15, 16, 126, 20)
        self._jButtonResRefresh.setBounds(718, 16, 80, 20)
        self._jButtonRemoveScan.setBounds(810, 16, 80, 20)
        self._scrollPane.setBounds(15, 45, 1200, 400)

        self._jResultTablePanel.add(self._jLabelResultScan)
        self._jResultTablePanel.add(self._jButtonResRefresh)
        self._jResultTablePanel.add(self._jButtonRemoveScan)
        self._jResultTablePanel.add(self._scrollPane)

        self._tabs = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self._tabs.setLeftComponent(messageEditor.getComponent())
        self._tabs.setRightComponent(messageLogEditor.getComponent())
        self._tabs.setDividerLocation(0.5)
        self._tabs.setDividerSize(10)
        self._tabs.setResizeWeight(0.5)

        self._jResultPanel.setLeftComponent(self._jResultTablePanel)
        self._jResultPanel.setRightComponent(self._tabs)
        self._jResultPanel.setDividerLocation(0.5)
        self._jResultPanel.setDividerSize(10)
        self._jResultPanel.setResizeWeight(0.5)

        self._jConfigTab = swing.JTabbedPane()
        self._jConfigTab.addTab("SQLMap API", self._jPanel)
        self._jConfigTab.addTab("SQLMap Scanner", self._jScrollPaneMain)
        self._jConfigTab.addTab("SQLMap Scan Remove", self._jStopScanPanel)
        self._jConfigTab.addTab("SQLMap Scan Results", self._jResultPanel)
        callbacks.customizeUiComponent(self._jConfigTab)
        callbacks.addSuiteTab(self)
        self.startAPI()
        self.getResults()
        self._scrollPane.setBounds(15, 45, self._jResultTablePanel.getWidth(), 440)
        self.getUiComponent().addComponentListener(self)

    def componentResized(self, event):
        self._scrollPane.setBounds(15, 45, self._jResultTablePanel.getWidth(), self._jResultTablePanel.getHeight() - 40)

    # Create a menu item if the appropriate section of the UI is selected
    def createMenuItems(self, invocation):
        menu = []
        j = swing.JMenuItem("SQLiPy Scan", None, actionPerformed=lambda x, inv=invocation: self.sqlMapScan(inv))
        j.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Q, InputEvent.CTRL_MASK))
        menu.append(j)
        return menu if menu else None

    def getTabCaption(self):
        return 'sqlmap api'

    def getUiComponent(self):
        return self._jConfigTab

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    def detectStringEncoding(self, s):
        codecs = ['ASCII', 'UTF-8', 'cp1252', 'latin-1', 'ISO 8859-1', 'ISO 8859-15', 'GBK', 'JIS', 'UCS-2', 'UCS-4',
                  'UTF-16', 'UTF-32', 'UTF-42']
        for i in codecs:
            try:
                s.encode(i)
                return i
            except UnicodeEncodeError:
                pass
        return False

    def sqlMapScan(self, invocation):
        try:
            invMessage = invocation.getSelectedMessages()
            message = invMessage[0]
            reqInfo = self._helpers.analyzeRequest(message)
            reqBody = message.getRequest()
            req = self._helpers.bytesToString(reqBody).decode('utf-8').encode('utf-8')
            self._jTextData.setText(req.decode('utf-8'))
            self.scanUrl = reqInfo.getUrl()
            self._jTextFieldURL.setText(str(reqInfo.getUrl()))
            self._jConfigTab.setSelectedComponent(self._jScrollPaneMain)
            parentTab = self._jConfigTab.getParent()
            parentTab.setSelectedComponent(self._jConfigTab)
        except Exception as e:
            print(e)
            print('Failed to add data to scan tab.')

    def printHeader(self):
        print('Burp interface to SQLMap API\nclay_nu.github.io\n\n')

    def saveConfig(self, button=None):
        global data, config_file
        data['host'] = self._jTextFieldIPListen.getText()
        data['port'] = self._jTextFieldPortListen.getText()
        data['user'] = str(self._jTextFieldUser.getText().encode('utf-8'))
        data['project'] = str(self._jTextFieldProject.getText().encode('utf-8'))
        data['options'] = json.loads(self._jTextOptions.getText().encode('utf-8'))
        f = open(config_file, 'w')
        f.seek(0)
        f.write(json.dumps(data))
        f.close()

    def startAPI(self, button=None):

        try:
            req = urllib2.Request('http://' + str(self._jTextFieldIPListen.getText()) + ':' + str(
                self._jTextFieldPortListen.getText()) + '/')
            req.add_header('Content-Type', 'application/json')
            resp = urllib2.urlopen(req, timeout=2)
            self._jLabelScanAPI.setText(
                self._jTextFieldIPListen.getText() + ':' + self._jTextFieldPortListen.getText())
            self._jLabelScanAPI.setForeground(Color.GREEN)
            self._jTextFieldScanIPListen.setText(self._jTextFieldIPListen.getText())
            self._jTextFieldScanPortListen.setText(self._jTextFieldPortListen.getText())
            self._jLabelAPIStatus.setText('SQLMap API IS CURRENTLY RUNNING!')
            self._jLabelAPIStatus.setForeground(Color.GREEN)

            print('SQLMap API started.\n')
        except Exception as e:

            self._jLabelScanAPI.setText('SQLMap API is NOT running!')
            self._jLabelScanAPI.setForeground(Color.RED)
            self._jLabelAPIStatus.setText("SQLMap API is NOT running!")
            self._jLabelAPIStatus.setForeground(Color.RED)
            print('sqlmap api is not running')
            self._jTextFieldScanIPListen.setText(self._jTextFieldIPListen.getText())
            self._jTextFieldScanPortListen.setText(self._jTextFieldPortListen.getText())

    def extensionUnloaded(self):
        pass

    def stopScan(self, button):
        req = urllib2.Request('http://' + str(self._jTextFieldScanIPListen.getText()) + ':' + str(
            self._jTextFieldScanPortListen.getText()) + '/delTask/' + str(
            self._jComboStopScan.getSelectedItem().split('-')[0]))
        resp = json.load(urllib2.urlopen(req, timeout=10))
        print('Scan stopped for ID: ' + self._jComboStopScan.getSelectedItem().split('-')[0] + '\n')
        self._jLabelStopStatus.setText(
            'Scan stopped for ID: ' + self._jComboStopScan.getSelectedItem().split('-')[0])
        self._jComboStopScan.removeItem(self._jComboStopScan.getSelectedItem())
        self.getResults()

        # print 'Failed to stop scan on ID: ' + self._jComboStopScan.getSelectedItem().split('-')[
        #     0] + ', likely already completed\n'
        # # self._jLabelStopStatus.setText(
        #     'Failed to stop scan on ID: ' + self._jComboStopScan.getSelectedItem().split('-')[
        #         0] + ', likely already completed')

    def removeScan(self, button):
        print('Removing Scan Stop Entry for ID: ' + self._jComboStopScan.getSelectedItem().split('-')[0] + '\n')
        self._jLabelStopStatus.setText(
            'Scan removed from stop tab for ID: ' + self._jComboStopScan.getSelectedItem().split('-')[0])
        self._jComboStopScan.removeItem(self._jComboStopScan.getSelectedItem())

    def startScan(self, messageInfo):
        print('start scan button clicked')
        try:
            url = 'http://' + str(self._jTextFieldScanIPListen.getText()) + ':' + str(
                self._jTextFieldScanPortListen.getText()) + '/singleRequest'
            scan_data = self._jTextData.getText().encode('utf-8')
            options = self._jTextOptions.getText().encode('utf-8')
            data = {
                "project": base64.urlsafe_b64encode(str(self._jTextFieldProject.getText().encode('utf-8'))),
                "request": base64.b64encode(scan_data),
                "options": json.loads(options)
            }
            if self._jTextFieldURL.getText().startswith('https'):
                data['options']['forceSSL'] = True
            req = urllib2.Request(url=url, data=json.dumps(data).encode('utf-8'))
            req.add_header('Content-Type', 'application/json')
            req.add_header('Cookie', 'user=' + str(self._jTextFieldUser.getText().encode('utf-8')))
            resp = json.load(urllib2.urlopen(req, timeout=10))
            if resp.get('tasks', []) != []:
                sqlitask = resp['tasks'][0]
                print('Created SQLMap Task: ' + sqlitask + '\n')
                # self._jComboLogs.addItem(sqlitask + '-' + self._jTextFieldURL.getText())
                self._jComboStopScan.addItem(sqlitask + '-' + self._jTextFieldURL.getText())
                print('Started SQLMap Scan on Task ' + sqlitask + ' - ' + self._jTextFieldURL.getText() + '\n')
            else:
                print('Failed to start SQLMap Scan for url' + str(self._jTextFieldURL))
        except:
            print(traceback.format_exc())
            print('SQLMap task creation failed\n')

    def getResults(self, button=None):
        self._jComboStopScan.removeAllItems()
        # self._jComboLogs.removeAllItems()
        url = 'http://' + str(self._jTextFieldScanIPListen.getText()) + ':' + str(
            self._jTextFieldScanPortListen.getText()) + '/getTaskList?project=' + base64.urlsafe_b64encode(
            str(self._jTextFieldProject.getText().encode('utf-8')))
        req = urllib2.Request(url=url)
        req.add_header('Content-Type', 'application/json')
        req.add_header('Cookie', 'user=' + str(self._jTextFieldUser.getText().encode('utf-8')))
        resp = json.load(urllib2.urlopen(req, timeout=10))
        self._model.setRowCount(0)
        order = {'Failed': 1, 'Exception': 2, None: 3, 'Pass': 4}
        resp_order = sorted(resp.items(), key=lambda x: order.get(x[1]["result"], 'Z'))
        for taskId, des in resp_order:
            self._model.addRow([taskId, des['status'], des['host'], des['uri'], des['result']])
            # self._jComboLogs.addItem(taskId + '-http://' + des['host']+des['uri'])
            self._jComboStopScan.addItem(taskId + '-http://' + des['host'] + des['uri'])

    def cleanResults(self, button):
        self._model.setRowCount(0)


class myTableListener(MouseAdapter):
    def __init__(self, table, host, port):
        global messageEditor, messageLogEditor
        self._table = table
        self._messageEditor = messageEditor
        self._messageLogEditor = messageLogEditor
        self._host = host
        self._port = port
        self.results = {
            'Pass': 'Pass',
            'Exception': 'Exception',
        }

    def mouseClicked(self, event):
        prefix = '''HTTP/1.0 200 OK
Content-Type: application/json

'''
        self._messageEditor.setMessage(''.encode(), False)
        self._messageLogEditor.setMessage(''.encode(), False)
        row = self._table.rowAtPoint(event.getPoint())
        taskid = self._table.getValueAt(row, 0)
        try:
            res = self.get_payload(taskid)
            resp = json.load(res)
            if resp['result'] != 'Failed':
                resp['detail'] = self.results[resp['result']]
            self._messageEditor.setMessage(bytes(prefix + json.dumps(resp).decode('utf-8')), False)
        except Exception as e:
            self._messageEditor.setMessage("the task is running or outdated".encode(), False)

        logdata = self.getLogs(taskid)
        self._messageLogEditor.setMessage(bytes(prefix + logdata.decode('utf-8')), False)

    def getLogs(self, taskID):
        # try:
        url = 'http://' + self._host + ':' + self._port + '/getLogs/' + taskID
        print(url)
        req = urllib2.Request(url)
        # try:
        res = urllib2.urlopen(req, timeout=5)
        resp = json.load(res)
        return json.dumps(resp)

        # except Exception as e:
        #     return 'The task `'+ taskID +'` has just started,please try again later!'

    def get_payload(self, taskid):
        req = urllib2.Request('http://' + self._host + ':' + self._port + '/getResult/' + taskid)
        req.add_header('Content-Type', 'application/json')
        resp = urllib2.urlopen(req, timeout=2)
        return resp
