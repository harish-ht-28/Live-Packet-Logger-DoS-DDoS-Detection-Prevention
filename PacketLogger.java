import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;


public class PacketLogger extends JFrame {
    private final DefaultTableModel tableModel;
    private final DefaultListModel<String> alertModel;
    private final JTextField filterField, tsharkPathField;
    private final JComboBox<String> ifaceCombo;
    private final JButton startButton, stopButton;
    private final JLabel statusBar;
    private final javax.swing.JProgressBar statusProgress;
    private final javax.swing.Timer filterDebounceTimer;
    private final javax.swing.table.TableRowSorter<DefaultTableModel> sorter;
    private final JTextField searchField;
    private final JLabel alertCountLabel;
    private final PacketCaptureService captureService;
    // track suspected IPs across the session so we can offer mitigation after stopping
    private final java.util.Set<String> suspectedIps = java.util.Collections.synchronizedSet(new java.util.HashSet<>());
    private final JButton mitigateButton;
    // dry-run removed; mitigation will run for real when requested
    private final JButton undoMitigateButton;
    // in-memory list of created mitigation records (for undo during this session)
    private final java.util.List<MitigationRecord> mitigationRecords = new java.util.ArrayList<>();
    private final java.io.File mitigationLogFile = new java.io.File(System.getProperty("user.dir"), "mitigation.log");
    // in-app capture-level blocklist (no admin required) — prevents the dashboard from seeing traffic from these IPs
    private final java.util.Set<String> blockedIps = java.util.Collections.synchronizedSet(new java.util.HashSet<>());
    private final javax.swing.JCheckBox autoBlockCheck; 
    private final JButton manageBlocklistButton;
    // pending scheduled blocks: ip -> Swing Timer
    private final java.util.Map<String, javax.swing.Timer> pendingBlockTimers = new java.util.HashMap<>();
    private final javax.swing.JSpinner blockDelaySpinner;
    // fixed thresholds (controls removed for simplicity)
    private static final int DEFAULT_PER_IP_THRESHOLD = 100;
    private static final int DEFAULT_TOTAL_THRESHOLD = 1000;
    private final javax.swing.JCheckBox simpleModeCheck;

    public PacketLogger() {
        // Use system look and feel for a professional native appearance
        try {
            javax.swing.UIManager.setLookAndFeel(javax.swing.UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        setTitle("Live Packet Logger & DOS/DDOS Detector Dashboard (TShark)");
        setSize(1100, 700);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        // create a small programmatic icon so the app looks polished on the taskbar
        try {
            java.awt.image.BufferedImage bi = new java.awt.image.BufferedImage(64, 64, java.awt.image.BufferedImage.TYPE_INT_ARGB);
            java.awt.Graphics2D g = bi.createGraphics();
            g.setColor(new java.awt.Color(32, 120, 255));
            g.fillOval(4, 4, 56, 56);
            g.setColor(java.awt.Color.WHITE);
            g.setFont(g.getFont().deriveFont(java.awt.Font.BOLD, 28f));
            g.drawString("P", 20, 44);
            g.dispose();
            setIconImage(bi);
        } catch (Throwable ignoredIcon) {}

        tableModel = new DefaultTableModel(new Object[]{"Timestamp", "Protocol", "Source", "Destination", "Info", "Filter"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // only allow editing of the Filter column (last column)
                return column == 5;
            }
        };
    JTable packetTable = new JTable(tableModel);
        packetTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = new int[]{220, 100, 140, 140, 320, 160};
        for (int i = 0; i < widths.length; i++) {
            packetTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
    // make the Filter column (index 5) editable with a single-click cell editor
    packetTable.setSurrendersFocusOnKeystroke(true);
    javax.swing.table.TableColumn filterCol = packetTable.getColumnModel().getColumn(5);
    filterCol.setCellEditor(new DefaultCellEditor(new JTextField()));
        packetTable.setFillsViewportHeight(true);

    // Create a sorter and a search field for quick filtering of packet rows
    sorter = new javax.swing.table.TableRowSorter<>(tableModel);
    packetTable.setRowSorter(sorter);
    searchField = new JTextField(18);
    // simple search box: filter rows that contain the text in any column
    searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
        private void apply() {
            String txt = searchField.getText().trim();
            if (txt.isEmpty()) {
                sorter.setRowFilter(null);
            } else {
                sorter.setRowFilter(javax.swing.RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(txt)));
            }
        }
        @Override
        public void insertUpdate(javax.swing.event.DocumentEvent e) { apply(); }
        @Override
        public void removeUpdate(javax.swing.event.DocumentEvent e) { apply(); }
        @Override
        public void changedUpdate(javax.swing.event.DocumentEvent e) { apply(); }
    });

    // Custom renderer to highlight rows that contain alert-like text in the Info column
    class AlertTableCellRenderer extends javax.swing.table.DefaultTableCellRenderer {
        @Override
        public java.awt.Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            java.awt.Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            try {
                int modelRow = table.convertRowIndexToModel(row);
                Object infoObj = tableModel.getValueAt(modelRow, 4);
                String info = infoObj != null ? infoObj.toString().toLowerCase() : "";
                if (!isSelected) {
                    if (info.contains("dos") || info.contains("ddos") || info.contains("possible")) {
                        c.setBackground(new java.awt.Color(255, 230, 230));
                    } else {
                        c.setBackground(java.awt.Color.WHITE);
                    }
                }
            } catch (Exception ignored) {}
            return c;
        }
    }
    packetTable.setDefaultRenderer(Object.class, new AlertTableCellRenderer());

    // Add a small toolbar with Refresh and Export features for a professional UI
    javax.swing.JToolBar toolBar = new javax.swing.JToolBar();
    toolBar.setFloatable(false);
        javax.swing.JButton refreshButton = new javax.swing.JButton("Refresh Interfaces");
        refreshButton.setToolTipText("Re-run TShark -D and refresh available interfaces");
        refreshButton.addActionListener(e -> populateInterfaces());
    javax.swing.JButton exportButton = new javax.swing.JButton("Refresh Interfaces & Show Blocked");
    exportButton.setToolTipText("Refresh interfaces and show currently blocked IPs");
        exportButton.addActionListener(e -> {
            populateInterfaces();
            // snapshot blocked IPs
            java.util.List<String> list = new java.util.ArrayList<>(blockedIps);
            if (list.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No IPs are currently blocked (in-app).", "Blocked IPs", JOptionPane.INFORMATION_MESSAGE);
            } else {
                StringBuilder sb = new StringBuilder();
                for (String ip : list) sb.append(ip).append('\n');
                JOptionPane.showMessageDialog(this, sb.toString(), "Blocked IPs", JOptionPane.INFORMATION_MESSAGE);
            }
        });
    toolBar.add(refreshButton);
    toolBar.add(exportButton);
    mitigateButton = new JButton("Mitigate Suspects");
    mitigateButton.setToolTipText("Block suspected attacker IPs using system firewall (requires admin)");
    mitigateButton.addActionListener(e -> mitigateSuspectedIps());
    mitigateButton.setEnabled(false);
    toolBar.add(mitigateButton);
    // dry-run checkbox removed per user request
    undoMitigateButton = new JButton("Undo Mitigation");
    undoMitigateButton.setToolTipText("Remove rules previously added by this tool (session undo)");
    undoMitigateButton.setEnabled(false);
    undoMitigateButton.addActionListener(e -> undoMitigations());
    toolBar.add(undoMitigateButton);
    autoBlockCheck = new javax.swing.JCheckBox("Auto-block in capture");
    autoBlockCheck.setToolTipText("When enabled, suspected IPs will be excluded from the live capture (no admin required)");
    autoBlockCheck.setSelected(true);
    toolBar.add(autoBlockCheck);
    manageBlocklistButton = new JButton("Manage Blocklist");
    manageBlocklistButton.addActionListener(e -> showManageBlocklistDialog());
    manageBlocklistButton.setEnabled(false);
    toolBar.add(manageBlocklistButton);
    // spinner to configure delay (seconds) before auto-blocking after an alert
    blockDelaySpinner = new javax.swing.JSpinner(new javax.swing.SpinnerNumberModel(5, 0, 600, 1));
    blockDelaySpinner.setToolTipText("Seconds to wait after an alert before auto-blocking the IP (0 = immediate)");
    toolBar.add(new javax.swing.JLabel(" Block delay (s): "));
    toolBar.add(blockDelaySpinner);
    // Simple mode: immediately block on alert and hide complex controls for demo clarity
    simpleModeCheck = new javax.swing.JCheckBox("Simple Auto-Block");
    simpleModeCheck.setToolTipText("When enabled, the dashboard will auto-block detected IPs immediately and simplify the UI for demos.");
    simpleModeCheck.setSelected(true);
    simpleModeCheck.addActionListener(e -> {
        boolean simple = simpleModeCheck.isSelected();
        // disable complex mitigation controls when simple mode is on
        mitigateButton.setEnabled(!simple);
        // dry-run control removed
        undoMitigateButton.setEnabled(!simple && !mitigationRecords.isEmpty());
        manageBlocklistButton.setEnabled(!simple || !blockedIps.isEmpty());
    });
    toolBar.add(simpleModeCheck);
    // thresholds are fixed now; UI simplified
    javax.swing.JButton demoAlert = new javax.swing.JButton("Generate Test Alert");
    demoAlert.setToolTipText("Create a sample alert for demo/testing");
    demoAlert.addActionListener(e -> {
        String sample = "192.0.2.123";
        showAlert("[Test] Possible DoS from IP " + sample + ": demo", true);
        flagSuspectedIp(sample);
    });
    toolBar.add(demoAlert);
    toolBar.addSeparator();
    toolBar.add(new javax.swing.JLabel("Search: "));
    toolBar.add(searchField);
    alertCountLabel = new JLabel("Alerts: 0");
    toolBar.addSeparator();
    toolBar.add(alertCountLabel);

    // create a menu bar for basic app actions
    javax.swing.JMenuBar menuBar = new javax.swing.JMenuBar();
    javax.swing.JMenu fileMenu = new javax.swing.JMenu("File");
    javax.swing.JMenuItem exitItem = new javax.swing.JMenuItem("Exit");
        exitItem.addActionListener(e -> System.exit(0));
    fileMenu.add(exitItem);
    javax.swing.JMenu viewMenu = new javax.swing.JMenu("View");
    javax.swing.JMenuItem refreshItem = new javax.swing.JMenuItem("Refresh Interfaces");
    refreshItem.addActionListener(a -> populateInterfaces());
    viewMenu.add(refreshItem);
    javax.swing.JMenu helpMenu = new javax.swing.JMenu("Help");
    javax.swing.JMenuItem aboutItem = new javax.swing.JMenuItem("About");
        aboutItem.addActionListener(e -> JOptionPane.showMessageDialog(this, "Live Packet Logger\nTShark frontend\nProfessional UI", "About", JOptionPane.INFORMATION_MESSAGE));
    helpMenu.add(aboutItem);
    menuBar.add(fileMenu);
    menuBar.add(viewMenu);
    menuBar.add(helpMenu);
    setJMenuBar(menuBar);

    // status progress bar initialization (debounce timer will be created later once fields exist)
    statusProgress = new javax.swing.JProgressBar();
    statusProgress.setStringPainted(false);

    alertModel = new DefaultListModel<>();
    JList<String> alertList = new JList<>(alertModel);
    alertList.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

    tsharkPathField = new JTextField("C:\\Program Files\\Wireshark\\tshark.exe", 30);
    ifaceCombo = new JComboBox<>();
    // try to populate interface list (will be silent on failure)
    SwingUtilities.invokeLater(this::populateInterfaces);
        filterField = new JTextField("", 15);

        startButton = new JButton("Start");
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);

    JPanel topPanel = new JPanel(new GridBagLayout());
    topPanel.setBackground(new java.awt.Color(240, 240, 255));
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.insets = new java.awt.Insets(6, 8, 6, 8);
    gbc.anchor = GridBagConstraints.WEST;
    gbc.gridy = 0;

    JLabel tsharkLabel = new JLabel("TShark Path:");
    tsharkLabel.setFont(tsharkLabel.getFont().deriveFont(java.awt.Font.BOLD));
    gbc.gridx = 0;
    gbc.weightx = 0.0;
    gbc.fill = GridBagConstraints.NONE;
    topPanel.add(tsharkLabel, gbc);

    // Path field (fills remaining space)
    gbc.gridx = 1;
    gbc.gridwidth = 3;
    gbc.weightx = 1.0;
    gbc.fill = GridBagConstraints.HORIZONTAL;
    tsharkPathField.setPreferredSize(new Dimension(520, 24));
    topPanel.add(tsharkPathField, gbc);

    // Browse button
    gbc.gridx = 4;
    gbc.gridwidth = 1;
    gbc.weightx = 0.0;
    gbc.fill = GridBagConstraints.NONE;
    JButton browseButton = new JButton("Browse");
        browseButton.addActionListener((java.awt.event.ActionEvent e) -> {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int res = chooser.showOpenDialog(PacketLogger.this);
        if (res == JFileChooser.APPROVE_OPTION) {
            java.io.File f = chooser.getSelectedFile();
            tsharkPathField.setText(f.getAbsolutePath());
        }
    });
    topPanel.add(browseButton, gbc);

    // Interface label + combo
    gbc.gridx = 5;
    JLabel ifaceLabel = new JLabel("Interface #: ");
    ifaceLabel.setFont(ifaceLabel.getFont().deriveFont(java.awt.Font.PLAIN, 12f));
    topPanel.add(ifaceLabel, gbc);
    gbc.gridx = 6;
    ifaceCombo.setPreferredSize(new Dimension(120, 24));
    topPanel.add(ifaceCombo, gbc);

    // Filter label + field
    gbc.gridx = 7;
    JLabel filterLabel = new JLabel("Filter: ");
    filterLabel.setFont(filterLabel.getFont().deriveFont(java.awt.Font.PLAIN, 12f));
    topPanel.add(filterLabel, gbc);
    gbc.gridx = 8;
    filterField.setColumns(16);
    filterField.setPreferredSize(new Dimension(160, 24));
    topPanel.add(filterField, gbc);

    // Start / Stop buttons on far right
    gbc.gridx = 9;
    gbc.anchor = GridBagConstraints.EAST;
    startButton.setPreferredSize(new Dimension(90, 28));
    stopButton.setPreferredSize(new Dimension(90, 28));
    topPanel.add(startButton, gbc);
    gbc.gridx = 10;
    topPanel.add(stopButton, gbc);
    gbc.anchor = GridBagConstraints.WEST;

    // Add a status bar at the bottom
    statusBar = new JLabel("Ready");
    statusBar.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
    statusBar.setOpaque(true);
    statusBar.setBackground(new java.awt.Color(230, 230, 230));

    // Make Enter in path/filter trigger Start when Start is enabled
    tsharkPathField.addActionListener((java.awt.event.ActionEvent ev) -> { if (startButton.isEnabled()) startButton.doClick(); });
    filterField.addActionListener((java.awt.event.ActionEvent ev) -> { if (startButton.isEnabled()) startButton.doClick(); });
    // typing in the filter field restarts capture after a debounce when running
    // create debounce timer now that filterField and startButton are initialized
    filterDebounceTimer = new javax.swing.Timer(800, ev -> {
        SwingUtilities.invokeLater(() -> {
            if (!startButton.isEnabled()) {
                String newFilter = filterField.getText().trim();
                restartCaptureWithFilter(newFilter);
            }
        });
    });
    filterDebounceTimer.setRepeats(false);
    filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
        private void changed() { filterDebounceTimer.restart(); }
        @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { changed(); }
        @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { changed(); }
        @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { changed(); }
    });

    // Listen for edits to the Filter column in the table
    tableModel.addTableModelListener(e -> {
        if (e.getType() == javax.swing.event.TableModelEvent.UPDATE) {
            int col = e.getColumn();
            int row = e.getFirstRow();
            if (col == 5 && row >= 0) {
                Object v = tableModel.getValueAt(row, col);
                String newFilter = v != null ? v.toString() : "";
                filterField.setText(newFilter);
                // if capture is running, restart with the new filter
                if (!startButton.isEnabled()) {
                    restartCaptureWithFilter(newFilter);
                }
            }
        }
    });

    JPanel mainPanel = new JPanel(new BorderLayout());
    mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 5));
    // add toolbar above the existing topPanel for a cleaner professional header
    JPanel northContainer = new JPanel(new BorderLayout());
    northContainer.add(toolBar, BorderLayout.NORTH);
    northContainer.add(topPanel, BorderLayout.CENTER);
    mainPanel.add(northContainer, BorderLayout.NORTH);
    JScrollPane tableScroll = new JScrollPane(packetTable);
    javax.swing.border.TitledBorder tb = BorderFactory.createTitledBorder("Packets");
    tb.setTitleFont(tb.getTitleFont().deriveFont(java.awt.Font.BOLD, 12f));
    tableScroll.setBorder(tb);
    packetTable.getTableHeader().setFont(packetTable.getTableHeader().getFont().deriveFont(java.awt.Font.BOLD));
    packetTable.setShowGrid(true);
    packetTable.setGridColor(new java.awt.Color(200, 200, 200));
    packetTable.setRowHeight(22);
    // header visual tweak
    packetTable.getTableHeader().setBackground(new java.awt.Color(245, 245, 245));
    packetTable.getTableHeader().setReorderingAllowed(false);
    mainPanel.add(tableScroll, BorderLayout.CENTER);
    // compose a professional status bar with progress on the right
    JPanel statusPanel = new JPanel(new BorderLayout(8, 0));
    statusPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
    statusPanel.add(statusBar, BorderLayout.CENTER);
    statusPanel.add(statusProgress, BorderLayout.EAST);
    mainPanel.add(statusPanel, BorderLayout.SOUTH);

    JPanel alertPanel = new JPanel(new BorderLayout());
    alertPanel.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 10));
    JScrollPane alertScroll = new JScrollPane(alertList);
    javax.swing.border.TitledBorder atb = BorderFactory.createTitledBorder("Alerts");
    atb.setTitleFont(atb.getTitleFont().deriveFont(java.awt.Font.BOLD, 12f));
    alertScroll.setBorder(atb);
    alertPanel.add(alertScroll, BorderLayout.CENTER);
        alertPanel.setPreferredSize(new Dimension(300, 0));

    JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, mainPanel, alertPanel);
    splitPane.setContinuousLayout(true);
    splitPane.setOneTouchExpandable(true);
    // give more room to the packets table so the Filter column is visible
    splitPane.setDividerLocation(920);
    splitPane.setResizeWeight(0.80);
        getContentPane().add(splitPane);

    captureService = new PacketCaptureService(this);

    // Context menu for packet table: copy row and show details
    javax.swing.JPopupMenu tablePopup = new javax.swing.JPopupMenu();
    javax.swing.JMenuItem copyRow = new javax.swing.JMenuItem("Copy Row");
        copyRow.addActionListener(e -> {
        int viewRow = packetTable.getSelectedRow();
        if (viewRow >= 0) {
            int modelRow = packetTable.convertRowIndexToModel(viewRow);
            StringBuilder sb = new StringBuilder();
            for (int c = 0; c < tableModel.getColumnCount(); c++) {
                Object v = tableModel.getValueAt(modelRow, c);
                if (c > 0) sb.append('\t');
                sb.append(v != null ? v.toString() : "");
            }
            java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(sb.toString());
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
        }
    });
    javax.swing.JMenuItem showDetails = new javax.swing.JMenuItem("Show Details");
        showDetails.addActionListener(e -> {
        int viewRow = packetTable.getSelectedRow();
        if (viewRow >= 0) {
            int modelRow = packetTable.convertRowIndexToModel(viewRow);
            Object info = tableModel.getValueAt(modelRow, 4);
            JOptionPane.showMessageDialog(PacketLogger.this, info != null ? info.toString() : "", "Packet Details", JOptionPane.INFORMATION_MESSAGE);
        }
    });
    tablePopup.add(copyRow);
    tablePopup.add(showDetails);
    packetTable.setComponentPopupMenu(tablePopup);
    packetTable.addMouseListener(new java.awt.event.MouseAdapter() {
        @Override public void mouseClicked(java.awt.event.MouseEvent e) {
            if (e.getClickCount() == 2) {
                int row = packetTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    packetTable.setRowSelectionInterval(row, row);
                    showDetails.doClick();
                }
            }
        }
    });

    // Improve visuals: alternate row colors in renderer (handled in AlertTableCellRenderer)

        startButton.addActionListener(e -> {
                startButton.setEnabled(false);
                stopButton.setEnabled(true);
                alertModel.clear();
                tableModel.setRowCount(0);
                    String tsharkPath = tsharkPathField.getText().trim();
                        String iface = (String) ifaceCombo.getSelectedItem();
                        if (iface == null) iface = "1";
                        // iface string is like "1. \\\Device\\NPF... (Name)" or similar - extract leading number if present
                        String ifaceIndex = iface.split("\\.", 2)[0].trim();
                    String filter = filterField.getText().trim();

                    // validate tshark path
                    java.io.File tsharkFile = new java.io.File(tsharkPath);
                    if (!tsharkFile.exists() || !tsharkFile.isFile()) {
                        showAlert("TShark executable not found at: " + tsharkPath, true);
                        setStatus("Ready");
                        startButton.setEnabled(true);
                        stopButton.setEnabled(false);
                        return;
                    }

                    // validate interface number loosely
                    try {
                        Integer.parseInt(ifaceIndex);
                        iface = ifaceIndex;
                    } catch (NumberFormatException nfe) {
                        showAlert("Interface selection invalid: " + iface, true);
                        setStatus("Ready");
                        startButton.setEnabled(true);
                        stopButton.setEnabled(false);
                        return;
                    }

                    setStatus("Starting capture...");
                    captureService.startCapture(tsharkPath, iface, filter);
                    setStatus("Capturing");
        });

        stopButton.addActionListener(e -> {
            captureService.stopCapture();
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            setStatus("Stopped");
            // enable mitigation UI if we have suspects
            onCaptureStopped();
        });

        // CSV Export helper
        // Exports only currently visible rows (after sorting/filtering) to a user-selected CSV file
    
    }

    private void populateInterfaces() {
        String tshark = tsharkPathField.getText().trim();
        if (tshark.isEmpty()) return;
        List<String> lines = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder(tshark, "-D");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String l;
                while ((l = r.readLine()) != null) {
                    lines.add(l.trim());
                }
            }
            // populate combo on EDT
            SwingUtilities.invokeLater(() -> {
                ifaceCombo.removeAllItems();
                for (String ln : lines) {
                    // often lines are like "1. \\Device... (Name)" - add directly
                    ifaceCombo.addItem(ln);
                }
                // try to select loopback if present
                for (int i = 0; i < ifaceCombo.getItemCount(); i++) {
                    String it = ifaceCombo.getItemAt(i).toLowerCase();
                    if (it.contains("loopback") || it.contains("loopback")) {
                        ifaceCombo.setSelectedIndex(i);
                        break;
                    }
                }
            });
        } catch (IOException ignored) {
        }
    }

    private void setStatus(String text) {
        if (statusBar != null) SwingUtilities.invokeLater(() -> statusBar.setText(text));
    }

    public void addPacketRow(Object[] data) {
        SwingUtilities.invokeLater(() -> tableModel.addRow(data));
    }

    private void restartCaptureWithFilter(String newFilter) {
        // stop old capture
        captureService.stopCapture();
        // enable UI appropriately
        setStatus("Restarting with new filter: " + newFilter);
        // start new capture with same path and selected iface
        String tsharkPath = tsharkPathField.getText().trim();
        String ifaceSelection = (String) ifaceCombo.getSelectedItem();
        String ifaceIndex = "1";
        if (ifaceSelection != null) ifaceIndex = ifaceSelection.split("\\.", 2)[0].trim();
        // if auto-block is enabled and we have blocked IPs, append a capture filter to exclude them
        String effectiveFilter = newFilter;
        if (autoBlockCheck.isSelected() && !blockedIps.isEmpty()) {
            StringBuilder excl = new StringBuilder();
            for (String b : blockedIps) {
                if (excl.length() > 0) excl.append(" and ");
                excl.append("not host ").append(b);
            }
            if (effectiveFilter == null || effectiveFilter.isEmpty()) effectiveFilter = excl.toString();
            else effectiveFilter = "(" + effectiveFilter + ") and (" + excl.toString() + ")";
        }
        captureService.startCapture(tsharkPath, ifaceIndex, effectiveFilter);
        setStatus("Capturing");
    }

    private void showManageBlocklistDialog() {
        // simple dialog to view/add/remove blocked IPs
        java.util.List<String> snapshot;
        synchronized (blockedIps) { snapshot = new java.util.ArrayList<>(blockedIps); }
        javax.swing.JList<String> list = new javax.swing.JList<>(snapshot.toArray(new String[0]));
        JScrollPane sp = new JScrollPane(list);
        sp.setPreferredSize(new Dimension(400, 200));
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(sp, BorderLayout.CENTER);
        JPanel ctl = new JPanel();
        JButton add = new JButton("Add");
        JButton remove = new JButton("Remove Selected");
        ctl.add(add); ctl.add(remove);
        panel.add(ctl, BorderLayout.SOUTH);
        add.addActionListener(e -> {
            String ip = JOptionPane.showInputDialog(this, "IP to block (e.g. 1.2.3.4):");
            if (ip != null && !ip.trim().isEmpty()) { blockedIps.add(ip.trim()); list.setListData(blockedIps.toArray(new String[0])); }
        });
        remove.addActionListener(e -> {
            java.util.List<String> sel = list.getSelectedValuesList();
            for (String s : sel) blockedIps.remove(s);
            list.setListData(blockedIps.toArray(new String[0]));
        });
        JOptionPane.showMessageDialog(this, panel, "Manage Blocklist", JOptionPane.PLAIN_MESSAGE);
    }

    public void showAlert(String msg, boolean popup) {
        SwingUtilities.invokeLater(() -> {
            alertModel.addElement(msg);
            // increment on-screen counter
            try {
                String t = alertCountLabel.getText();
                int n = 0;
                if (t != null && t.startsWith("Alerts:")) {
                    String s = t.substring(7).trim();
                    n = Integer.parseInt(s);
                }
                n++;
                alertCountLabel.setText("Alerts: " + n);
            } catch (Exception ignored) {}
            if (popup) {
                JOptionPane.showMessageDialog(this, msg, "Alert!", JOptionPane.WARNING_MESSAGE);
            }
            // enable manage blocklist button if we have suspects
            manageBlocklistButton.setEnabled(!suspectedIps.isEmpty());
        });
    }

    // announce a block action in the UI (alerts list + optional popup)
    public void announceBlock(String ip, String reason) {
        String msg = "AUTO-BLOCK: " + ip + " - " + reason;
        // add to alerts and show a popup so the demo clearly shows the block
        showAlert(msg, true);
    }

    // record a suspected IP so it can be mitigated later
    public void flagSuspectedIp(String ip) {
        if (ip == null || ip.isEmpty() || ip.equals("-")) return;
        suspectedIps.add(ip);
        // If simple mode is on, block immediately (demo-friendly)
        if (simpleModeCheck.isSelected()) {
            blockedIps.add(ip);
            announceBlock(ip, "Simple Mode");
            restartCaptureWithFilter(filterField.getText().trim());
            manageBlocklistButton.setEnabled(true);
            return;
        }
        // otherwise schedule block after configured delay if auto-block enabled
        if (autoBlockCheck.isSelected()) {
            int delay = ((Number) blockDelaySpinner.getValue()).intValue();
            if (delay <= 0) {
                // immediate
                blockedIps.add(ip);
                announceBlock(ip, "Auto-Block (immediate)");
                // restart capture to apply
                restartCaptureWithFilter(filterField.getText().trim());
                manageBlocklistButton.setEnabled(true);
            } else {
                // schedule a Swing timer
                javax.swing.Timer t = new javax.swing.Timer(delay * 1000, ev -> {
                    blockedIps.add(ip);
                    announceBlock(ip, "Auto-Block (scheduled)");
                    pendingBlockTimers.remove(ip);
                    restartCaptureWithFilter(filterField.getText().trim());
                    manageBlocklistButton.setEnabled(true);
                });
                t.setRepeats(false);
                pendingBlockTimers.put(ip, t);
                t.start();
            }
        }
    }

    // Offer mitigation: prompt user and try to add firewall rules to block the suspected IPs.
    // This is best-effort and will require admin privileges. We show the commands and run them where permitted.
    public void mitigateSuspectedIps() {
        java.util.List<String> ips;
        synchronized (suspectedIps) {
            ips = new java.util.ArrayList<>(suspectedIps);
        }
        if (ips.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No suspected IPs to mitigate.", "Mitigation", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("The following IPs were flagged as suspected attackers:\n\n");
        for (String ip : ips) sb.append(ip).append('\n');
        sb.append('\n').append("Do you want to attempt to block them now? (This requires admin privileges)");
        int res = JOptionPane.showConfirmDialog(this, sb.toString(), "Mitigate Suspected IPs", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (res != JOptionPane.YES_OPTION) return;

        // run mitigation per platform
        String os = System.getProperty("os.name").toLowerCase();
    for (String ip : ips) {
            try {
                if (os.contains("win")) {
                    // Windows: use netsh advfirewall to block IP
                    // example: netsh advfirewall firewall add rule name="Block IP 1.2.3.4" dir=in action=block remoteip=1.2.3.4
                    List<String> cmd = new ArrayList<>();
                    cmd.add("netsh"); cmd.add("advfirewall"); cmd.add("firewall"); cmd.add("add"); cmd.add("rule");
                    cmd.add("name=Block_" + ip);
                    cmd.add("dir=in"); cmd.add("action=block"); cmd.add("remoteip=" + ip);
                    String ruleName = "Block_" + ip;
                    String fullCommand = String.join(" ", cmd);
                    MitigationRecord rec = new MitigationRecord(System.currentTimeMillis(), "windows", ip, ruleName, fullCommand, true, false);
                    ProcessBuilder pb = new ProcessBuilder(cmd);
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                        String line;
                        StringBuilder out = new StringBuilder();
                        while ((line = r.readLine()) != null) out.append(line).append('\n');
                        showAlert("Mitigation output for " + ip + ":\n" + out.toString(), false);
                    }
                    mitigationRecords.add(rec);
                    logMitigationRecord(rec);
                    undoMitigateButton.setEnabled(true);
                } else {
                    // assume linux-like: use iptables (requires root)
                    List<String> cmd = new ArrayList<>();
                    cmd.add("/bin/sh"); cmd.add("-c");
                    cmd.add("iptables -A INPUT -s " + ip + " -j DROP");
                    String full = String.join(" ", cmd);
                    MitigationRecord rec = new MitigationRecord(System.currentTimeMillis(), "iptables", ip, "", full, true, false);
                    ProcessBuilder pb = new ProcessBuilder(cmd);
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                        String line; StringBuilder out = new StringBuilder();
                        while ((line = r.readLine()) != null) out.append(line).append('\n');
                        showAlert("Mitigation output for " + ip + ":\n" + out.toString(), false);
                    }
                    mitigationRecords.add(rec);
                    logMitigationRecord(rec);
                    undoMitigateButton.setEnabled(true);
                }
            } catch (IOException ex) {
                showAlert("Failed to apply mitigation for " + ip + ": " + ex.getMessage(), true);
            }
        }
        // clear suspected list after attempt
        suspectedIps.clear();
        JOptionPane.showMessageDialog(this, "Mitigation attempt finished. Check alerts for details.", "Mitigation", JOptionPane.INFORMATION_MESSAGE);
    }

    // Append a mitigation record to the log file (JSON line)
    private void logMitigationRecord(MitigationRecord r) {
        try (java.io.FileWriter fw = new java.io.FileWriter(mitigationLogFile, true);
             java.io.BufferedWriter bw = new java.io.BufferedWriter(fw);
             java.io.PrintWriter out = new java.io.PrintWriter(bw)) {
            out.println(r.toLine());
        } catch (IOException ex) {
            showAlert("Failed to write mitigation log: " + ex.getMessage(), false);
        }
    }

    // Undo mitigation for records created during this session
    private void undoMitigations() {
        if (mitigationRecords.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No mitigation records to undo.", "Undo Mitigation", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(this, "Undo all mitigation rules added by this session?", "Undo Mitigation", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;
        String os = System.getProperty("os.name").toLowerCase();
        for (MitigationRecord r : new ArrayList<>(mitigationRecords)) {
            try {
                if (r.backend.equals("windows")) {
                    // netsh advfirewall firewall delete rule name=Block_<ip>
                    List<String> cmd = new ArrayList<>();
                    cmd.add("netsh"); cmd.add("advfirewall"); cmd.add("firewall"); cmd.add("delete"); cmd.add("rule");
                    cmd.add("name=" + r.ruleName);
                    ProcessBuilder pb = new ProcessBuilder(cmd);
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                        StringBuilder out = new StringBuilder();
                        String ln;
                        while ((ln = br.readLine()) != null) out.append(ln).append('\n');
                        showAlert("Undo output for " + r.ip + ":\n" + out.toString(), false);
                    }
                } else if (r.backend.equals("iptables")) {
                    List<String> cmd = new ArrayList<>();
                    cmd.add("/bin/sh"); cmd.add("-c");
                    cmd.add("iptables -D INPUT -s " + r.ip + " -j DROP");
                    ProcessBuilder pb = new ProcessBuilder(cmd);
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                        StringBuilder out = new StringBuilder();
                        String ln;
                        while ((ln = br.readLine()) != null) out.append(ln).append('\n');
                        showAlert("Undo output for " + r.ip + ":\n" + out.toString(), false);
                    }
                }
            } catch (IOException ex) {
                showAlert("Failed to undo mitigation for " + r.ip + ": " + ex.getMessage(), true);
            }
            mitigationRecords.remove(r);
        }
        // log undo action
        try (java.io.FileWriter fw = new java.io.FileWriter(mitigationLogFile, true);
             java.io.BufferedWriter bw = new java.io.BufferedWriter(fw);
             java.io.PrintWriter out = new java.io.PrintWriter(bw)) {
            out.println("UNDO:" + System.currentTimeMillis());
        } catch (IOException ex) {
            // ignore
        }
        undoMitigateButton.setEnabled(!mitigationRecords.isEmpty());
        JOptionPane.showMessageDialog(this, "Undo completed (attempted). Review alerts for details.", "Undo Mitigation", JOptionPane.INFORMATION_MESSAGE);
    }

    // Simple persistence format (pipe-separated) for each mitigation record
    private static class MitigationRecord {
        final long ts; final String backend; final String ip; final String ruleName; final String command; final boolean success; final boolean dryRun;
        MitigationRecord(long ts, String backend, String ip, String ruleName, String command, boolean success, boolean dryRun) {
            this.ts = ts; this.backend = backend; this.ip = ip; this.ruleName = ruleName; this.command = command; this.success = success; this.dryRun = dryRun;
        }
        String toLine() {
            // escape pipes by replacing
            return ts + "|" + backend + "|" + ip + "|" + ruleName.replace("|","_") + "|" + command.replace("|","_") + "|" + (success?"1":"0") + "|" + (dryRun?"1":"0");
        }
    }

    public void updateAlertOnLastRow(String alertText) {
        SwingUtilities.invokeLater(() -> {
            int lastRow = tableModel.getRowCount() - 1;
            if (lastRow >= 0) {
                // append alert text to the Info column so it's visible in the table
                Object existing = tableModel.getValueAt(lastRow, 4);
                String newInfo = (existing != null ? existing.toString() + " | " : "") + alertText;
                tableModel.setValueAt(newInfo, lastRow, 4);
            }
        });
    }

    // Called when capture stops to enable mitigation UI if needed
    public void onCaptureStopped() {
        SwingUtilities.invokeLater(() -> {
            mitigateButton.setEnabled(!suspectedIps.isEmpty());
        });
    }

    // removed threshold getters; using fixed defaults

    // export function removed per user request

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            PacketLogger app = new PacketLogger();
            app.setVisible(true);
        });
    }

    // --------- PacketCaptureService definition ----------
    private static class PacketCaptureService {
        private Process tsharkProcess;
        private final PacketLogger dashboard;
        private final Map<String, Integer> ipPacketCounts = new HashMap<>();
        private int totalPackets = 0;
        private long lastTimestamp = System.currentTimeMillis();

        public PacketCaptureService(PacketLogger dashboard) {
            this.dashboard = dashboard;
        }

        public void startCapture(String tsharkPath, String iface, String filter) {
            Thread captureThread = new Thread(() -> {
                try {
                    List<String> cmd = new ArrayList<>();
                    cmd.add(tsharkPath);
                    cmd.add("-i");
                    cmd.add(iface);
                    // Force line-buffered output so we get lines promptly over the pipe
                    cmd.add("-l");
                    if (filter != null && !filter.isEmpty()) {
                        cmd.add("-f");
                        cmd.add(filter);
                    }
                    cmd.add("-T");
                    cmd.add("fields");
                    cmd.add("-e");
                    cmd.add("frame.time");
                    cmd.add("-e");
                    cmd.add("_ws.col.Protocol");
                    cmd.add("-e");
                    cmd.add("ip.src");
                    cmd.add("-e");
                    cmd.add("ip.dst");
                    cmd.add("-e");
                    cmd.add("_ws.col.Info");

                    ProcessBuilder pb = new ProcessBuilder(cmd);
                    pb.redirectErrorStream(true);

                    tsharkProcess = pb.start();
                    if (tsharkProcess == null || !tsharkProcess.isAlive()) {
                        dashboard.showAlert("Failed to start TShark process.", true);
                        dashboard.setStatus("Error starting TShark");
                        return;
                    } else {
                        dashboard.setStatus("TShark started (iface: " + iface + ")");
                    }

                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(tsharkProcess.getInputStream()))) {
                        String line;
                        while ((line = reader.readLine()) != null && tsharkProcess.isAlive()) {
                            System.out.println("[RAW] " + line); // Debug output
                                    Object[] parsed = parseTsharkLine(line);
                                    if (parsed != null) {
                                        // parsed[4] is the Info column; filter out noisy ICMP "Destination unreachable" lines
                                        String info = parsed[4] != null ? parsed[4].toString() : "";
                                        if (info.toLowerCase().contains("destination unreachable")) {
                                            // skip noisy unreachable messages
                                        } else {
                                            // include the active filter string in each row so user sees it in the table
                                            Object[] row = new Object[6];
                                            System.arraycopy(parsed, 0, row, 0, 5);
                                            row[5] = filter != null && !filter.isEmpty() ? filter : "";
                                            dashboard.addPacketRow(row);

                                            String srcIp = (parsed.length > 2 && parsed[2] instanceof String) ? (String) parsed[2] : "";
                                            analyzePacket(srcIp);
                                        }
                                    }
                        }
                    }
                } catch (IOException e) {
                    // capture stack trace to show in UI instead of printing to console
                    String exSummary = e.getClass().getSimpleName() + ": " + e.getMessage();
                    dashboard.showAlert("Error starting TShark: " + exSummary, true);
                    dashboard.setStatus("Error: " + exSummary);
                } finally {
                    stopCapture();
                    dashboard.showAlert("Capture Stopped.", false);
                    dashboard.setStatus("Stopped");
                }
            });
            captureThread.start();
        }

        public void stopCapture() {
            if (tsharkProcess != null) {
                tsharkProcess.destroy();
                tsharkProcess = null;
                // notify UI
                dashboard.setStatus("Stopped");
                dashboard.onCaptureStopped();
            }
        }

        private Object[] parseTsharkLine(String line) {
            String[] parts = line.split("\t", -1);
            if (parts.length < 5) return null;
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].isEmpty()) parts[i] = "-";
            }
            // fields were requested in order: frame.time, _ws.col.Protocol, ip.src, ip.dst, _ws.col.Info
            return new Object[]{
                    parts[0], // timestamp
                    parts[1], // protocol
                    parts[2], // source IP
                    parts[3], // destination IP
                    parts[4]  // info
            };
        }

        private void analyzePacket(String srcIp) {
            if (srcIp == null || srcIp.isEmpty() || srcIp.equals("-")) return;
            totalPackets++;
            ipPacketCounts.put(srcIp, ipPacketCounts.getOrDefault(srcIp, 0) + 1);
            long now = System.currentTimeMillis();
            if (now - lastTimestamp > 1000) {
                int perIpThreshold = DEFAULT_PER_IP_THRESHOLD;
                int totalThreshold = DEFAULT_TOTAL_THRESHOLD;
                for (Map.Entry<String, Integer> entry : ipPacketCounts.entrySet()) {
                    if (entry.getValue() > perIpThreshold) {
                        String alert = "Possible DoS from IP " + entry.getKey() + ": " + entry.getValue() + " pkts/sec";
                        dashboard.showAlert(alert, false);
                        dashboard.updateAlertOnLastRow(alert);
                        dashboard.flagSuspectedIp(entry.getKey());
                    }
                }
                if (totalPackets > totalThreshold) {
                    String alert = "Possible DDoS: total packet surge (" + totalPackets + " pkts/sec)";
                    dashboard.showAlert(alert, false);
                    dashboard.updateAlertOnLastRow(alert);
                }
                ipPacketCounts.clear();
                totalPackets = 0;
                lastTimestamp = now;
            }
        }
    }
}
