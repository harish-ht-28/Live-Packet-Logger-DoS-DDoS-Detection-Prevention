import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class PacketLoggerDetector extends JFrame {
    private final DefaultTableModel tableModel;
    private final DefaultListModel<String> alertModel;
    private final JTextField filterField, tsharkPathField;
    private final JComboBox<String> ifaceCombo;
    private final JButton startButton, stopButton;
    private final JLabel statusBar;
    private final PacketCaptureService captureService;

    public PacketLoggerDetector() {
        setTitle("Live Packet Logger & DOS/DDOS Detector Dashboard (TShark)");
        setSize(1100, 600);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

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
    browseButton.addActionListener((java.awt.event.ActionEvent ev) -> {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int res = chooser.showOpenDialog(PacketLoggerDetector.this);
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
    filterField.addActionListener((java.awt.event.ActionEvent ev) -> {
        // if capture is running, restart with new filter
        if (!startButton.isEnabled()) {
            String newFilter = filterField.getText().trim();
            restartCaptureWithFilter(newFilter);
        } else if (startButton.isEnabled()) {
            startButton.doClick();
        }
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
    mainPanel.add(topPanel, BorderLayout.NORTH);
    JScrollPane tableScroll = new JScrollPane(packetTable);
    tableScroll.setBorder(BorderFactory.createTitledBorder("Packets"));
    packetTable.getTableHeader().setFont(packetTable.getTableHeader().getFont().deriveFont(java.awt.Font.BOLD));
    packetTable.setShowGrid(true);
    packetTable.setGridColor(new java.awt.Color(200, 200, 200));
    mainPanel.add(tableScroll, BorderLayout.CENTER);
    mainPanel.add(statusBar, BorderLayout.SOUTH);

    JPanel alertPanel = new JPanel(new BorderLayout());
    alertPanel.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 10));
    JScrollPane alertScroll = new JScrollPane(alertList);
    alertScroll.setBorder(BorderFactory.createTitledBorder("Alerts"));
    alertPanel.add(alertScroll, BorderLayout.CENTER);
        alertPanel.setPreferredSize(new Dimension(300, 0));

    JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, mainPanel, alertPanel);
    // give more room to the packets table so the Filter column is visible
    splitPane.setDividerLocation(920);
    splitPane.setResizeWeight(0.80);
        getContentPane().add(splitPane);

        captureService = new PacketCaptureService(this);

        startButton.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
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
            }
        });

        stopButton.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                captureService.stopCapture();
                startButton.setEnabled(true);
                stopButton.setEnabled(false);
                setStatus("Stopped");
            }
        });
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
        captureService.startCapture(tsharkPath, ifaceIndex, newFilter);
        setStatus("Capturing");
    }

    public void showAlert(String msg, boolean popup) {
        SwingUtilities.invokeLater(() -> {
            alertModel.addElement(msg);
            if (popup) {
                JOptionPane.showMessageDialog(this, msg, "Alert!", JOptionPane.WARNING_MESSAGE);
            }
        });
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

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            PacketLoggerDetector dashboard = new PacketLoggerDetector();
            dashboard.setVisible(true);
        });
    }

    // --------- PacketCaptureService definition ----------
    private static class PacketCaptureService {
        private Process tsharkProcess;
        private final PacketLoggerDetector dashboard;
        private final Map<String, Integer> ipPacketCounts = new HashMap<>();
        private int totalPackets = 0;
        private long lastTimestamp = System.currentTimeMillis();

        public PacketCaptureService(PacketLoggerDetector dashboard) {
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
                for (Map.Entry<String, Integer> entry : ipPacketCounts.entrySet()) {
                    if (entry.getValue() > 100) {
                        String alert = "Possible DoS from IP " + entry.getKey() + ": " + entry.getValue() + " pkts/sec";
                        dashboard.showAlert(alert, false);
                        dashboard.updateAlertOnLastRow(alert);
                    }
                }
                if (totalPackets > 1000) {
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
