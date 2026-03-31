package com.portswigger.oauthcheck;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

/**
 * Swing panel registered as a Burp Suite tab.
 * Allows manual target entry and displays all check results in a sortable table.
 */
public class OAuthScanPanel extends JPanel {

    // ─── Table model ──────────────────────────────────────────────────────────
    private static final String[] COLUMNS = {
        "Check", "Result", "Severity", "Confidence", "Evidence"
    };

    private final DefaultTableModel tableModel = new DefaultTableModel(COLUMNS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };

    // ─── Widgets ──────────────────────────────────────────────────────────────
    private final JTextField urlField   = new JTextField(50);
    private final JButton    scanButton = new JButton("Run OAuth Checks");
    private final JTable     table      = new JTable(tableModel);
    private final JTextArea  detailArea = new JTextArea(10, 80);
    private final JLabel     statusBar  = new JLabel(" Ready");

    private final OAuthScanner scanner  = new OAuthScanner();

    public OAuthScanPanel() {
        super(new BorderLayout(4, 4));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildCentrePanel(), BorderLayout.CENTER);
        add(statusBar, BorderLayout.SOUTH);
    }

    // ─── Top: URL entry + scan button ────────────────────────────────────────
    private JPanel buildTopPanel() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        p.setBorder(BorderFactory.createTitledBorder("Target"));

        urlField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        urlField.setToolTipText("e.g. https://accounts.example.com");

        scanButton.setBackground(new Color(220, 60, 50));
        scanButton.setForeground(Color.WHITE);
        scanButton.setFont(scanButton.getFont().deriveFont(Font.BOLD));
        scanButton.addActionListener(e -> startScan());

        p.add(new JLabel("Base URL:"));
        p.add(urlField);
        p.add(scanButton);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            tableModel.setRowCount(0);
            detailArea.setText("");
            statusBar.setText(" Ready");
        });
        p.add(clearBtn);
        return p;
    }

    // ─── Centre: results table + detail pane ─────────────────────────────────
    private JSplitPane buildCentrePanel() {
        // Table
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(22);
        table.setAutoCreateRowSorter(true);
        table.getTableHeader().setReorderingAllowed(false);

        // Column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(320);
        table.getColumnModel().getColumn(1).setPreferredWidth(90);
        table.getColumnModel().getColumn(2).setPreferredWidth(80);
        table.getColumnModel().getColumn(3).setPreferredWidth(90);
        table.getColumnModel().getColumn(4).setPreferredWidth(400);

        // Row colour renderer
        table.setDefaultRenderer(Object.class, new SeverityRenderer());

        // Selection → detail pane
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                int modelRow = table.convertRowIndexToModel(table.getSelectedRow());
                showDetail(modelRow);
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Results"));

        // Detail
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Detail"));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        split.setResizeWeight(0.65);
        return split;
    }

    // ─── Scan logic (runs in background thread) ───────────────────────────────
    private final List<OAuthCheckResult> allResults = new ArrayList<>();

    public void startScan() {
        String target = urlField.getText().trim();
        if (target.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "Please enter a base URL, e.g. https://auth.example.com",
                "No target", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!target.startsWith("http")) target = "https://" + target;

        tableModel.setRowCount(0);
        allResults.clear();
        detailArea.setText("");
        scanButton.setEnabled(false);
        statusBar.setText(" Scanning " + target + " …");

        final String finalTarget = target;
        ExecutorService exec = Executors.newSingleThreadExecutor();
        exec.submit(() -> {
            try {
                List<OAuthCheckResult> results = scanner.runFromUrl(finalTarget);
                SwingUtilities.invokeLater(() -> {
                    for (OAuthCheckResult r : results) {
                        addResult(r);
                    }
                    long vulnCount = results.stream().filter(OAuthCheckResult::isVulnerable).count();
                    statusBar.setText(" Scan complete – "
                        + results.size() + " findings, "
                        + vulnCount + " potential vulnerabilities.");
                    scanButton.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusBar.setText(" Error: " + ex.getMessage());
                    scanButton.setEnabled(true);
                });
            }
        });
        exec.shutdown();
    }

    /** Called from the extension when a request is identified as OAuth traffic. */
    public void addResult(OAuthCheckResult result) {
        allResults.add(result);
        tableModel.addRow(new Object[]{
            result.getCheckName(),
            result.isVulnerable() ? "⚠ VULNERABLE" : "✓ OK",
            result.getSeverity(),
            result.getConfidence(),
            result.getEvidence()
        });
    }

    /** Prefill the URL field (called from context menu). */
    public void setTargetUrl(String url) {
        urlField.setText(url);
    }

    private void showDetail(int modelRow) {
        if (modelRow < 0 || modelRow >= allResults.size()) return;
        OAuthCheckResult r = allResults.get(modelRow);
        StringBuilder sb = new StringBuilder();
        sb.append("╔══ ").append(r.getCheckName()).append(" ══\n\n");
        sb.append("Result    : ").append(r.isVulnerable() ? "VULNERABLE" : "Not Vulnerable").append("\n");
        sb.append("Severity  : ").append(r.getSeverity()).append("\n");
        sb.append("Confidence: ").append(r.getConfidence()).append("\n\n");
        sb.append("── Detail ──────────────────────────────────────────────────────────\n");
        sb.append(r.getDetail()).append("\n\n");
        if (!r.getRemediation().isEmpty()) {
            sb.append("── Remediation ─────────────────────────────────────────────────────\n");
            sb.append(r.getRemediation()).append("\n\n");
        }
        if (!r.getEvidence().isEmpty()) {
            sb.append("── Evidence ────────────────────────────────────────────────────────\n");
            sb.append(r.getEvidence()).append("\n");
        }
        if (!r.getRequestSent().isEmpty()) {
            sb.append("\n── Request ─────────────────────────────────────────────────────────\n");
            sb.append(r.getRequestSent()).append("\n");
        }
        if (!r.getResponseReceived().isEmpty()) {
            sb.append("\n── Response ────────────────────────────────────────────────────────\n");
            sb.append(r.getResponseReceived()).append("\n");
        }
        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    // ─── Renderer: colour rows by severity / result ───────────────────────────
    private static class SeverityRenderer extends DefaultTableCellRenderer {
        private static final Color HIGH_BG   = new Color(255, 220, 220);
        private static final Color MED_BG    = new Color(255, 243, 205);
        private static final Color LOW_BG    = new Color(220, 235, 255);
        private static final Color OK_BG     = new Color(230, 255, 230);
        private static final Color DEFAULT_BG= Color.WHITE;

        @Override
        public Component getTableCellRendererComponent(JTable t, Object val,
                boolean sel, boolean foc, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, val, sel, foc, row, col);
            if (!sel) {
                int modelRow = t.convertRowIndexToModel(row);
                Object result = t.getModel().getValueAt(modelRow, 1);
                Object sev    = t.getModel().getValueAt(modelRow, 2);
                String resultStr = result != null ? result.toString() : "";
                String sevStr    = sev    != null ? sev.toString()    : "";

                if (resultStr.contains("VULNERABLE")) {
                    switch (sevStr) {
                        case "HIGH":   c.setBackground(HIGH_BG);  break;
                        case "MEDIUM": c.setBackground(MED_BG);   break;
                        case "LOW":    c.setBackground(LOW_BG);   break;
                        default:       c.setBackground(DEFAULT_BG);
                    }
                } else {
                    c.setBackground(OK_BG);
                }
            }
            return c;
        }
    }
}
