package com.parth.darkwebmonitor.controller;

import com.parth.darkwebmonitor.model.MonitoredSource;
import com.parth.darkwebmonitor.model.ScanResult;
import com.parth.darkwebmonitor.model.ThreatIndicator;
import com.parth.darkwebmonitor.repository.MonitoredSourceRepository;
import com.parth.darkwebmonitor.repository.ScanResultRepository;
import com.parth.darkwebmonitor.repository.ThreatIndicatorRepository;
import com.parth.darkwebmonitor.service.DomainIntelligenceService;
import com.parth.darkwebmonitor.service.HibpService;
import com.parth.darkwebmonitor.service.OnionMonitoringService;
import com.parth.darkwebmonitor.service.PdfReportService;
import com.parth.darkwebmonitor.service.TorService;
import com.parth.darkwebmonitor.service.UsernameIntelligenceService;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

@Controller
public class DashboardController {

    private final ScanResultRepository scanResultRepository;
    private final MonitoredSourceRepository monitoredSourceRepository;
    private final ThreatIndicatorRepository threatIndicatorRepository;

    private final TorService torService;
    private final OnionMonitoringService onionMonitoringService;
    private final HibpService hibpService;
    private final PdfReportService pdfReportService;
    private final DomainIntelligenceService domainIntelligenceService;
    private final UsernameIntelligenceService usernameIntelligenceService;

    public DashboardController(
            ScanResultRepository scanResultRepository,
            MonitoredSourceRepository monitoredSourceRepository,
            ThreatIndicatorRepository threatIndicatorRepository,
            TorService torService,
            OnionMonitoringService onionMonitoringService,
            HibpService hibpService,
            PdfReportService pdfReportService,
            DomainIntelligenceService domainIntelligenceService,
            UsernameIntelligenceService usernameIntelligenceService) {

        this.scanResultRepository = scanResultRepository;
        this.monitoredSourceRepository = monitoredSourceRepository;
        this.threatIndicatorRepository = threatIndicatorRepository;
        this.torService = torService;
        this.onionMonitoringService = onionMonitoringService;
        this.hibpService = hibpService;
        this.pdfReportService = pdfReportService;
        this.domainIntelligenceService = domainIntelligenceService;
        this.usernameIntelligenceService =
                usernameIntelligenceService;
    }

    @GetMapping("/")
    public String dashboard(Model model) {

        List<ScanResult> scanResults =
                scanResultRepository.findAll();

        List<ThreatIndicator> indicators =
                threatIndicatorRepository.findAll();

        long totalScans = scanResults.size();

        long exposuresDetected =
                scanResults.stream()
                        .filter(scan ->
                                scan.getStatus() != null &&
                                scan.getStatus()
                                        .toUpperCase()
                                        .contains("EXPOSURE FOUND"))
                        .count();

        long threatAlerts =
                indicators.stream()
                        .filter(indicator ->
                                "HIGH".equalsIgnoreCase(
                                        indicator.getSeverity())
                                        ||
                                "CRITICAL".equalsIgnoreCase(
                                        indicator.getSeverity()))
                        .count();

        model.addAttribute("scanResults", scanResults);
        model.addAttribute("totalScans", totalScans);
        model.addAttribute("exposuresDetected", exposuresDetected);
        model.addAttribute("threatAlerts", threatAlerts);

        if (!scanResults.isEmpty()) {

            model.addAttribute(
                    "latestScan",
                    scanResults.get(
                            scanResults.size() - 1)
            );
        }

        return "dashboard";
    }

    @PostMapping("/scan")
    public String scan(
            @RequestParam("target") String target) {

        if (target == null ||
                target.trim().isEmpty()) {

            return "redirect:/";
        }

        target = target.trim();

        ScanResult scan = new ScanResult();
        scan.setTarget(target);

        // ==============================
        // EMAIL
        // ==============================

        if (target.contains("@")) {

            scan.setType("Email");
            scan.setSource("Have I Been Pwned");

            HibpService.HibpResult result =
                    hibpService.checkEmail(target);

            if (result.demoMode()) {

                scan.setStatus(
                        "DEMO - API NOT CONFIGURED");

                scan.setRisk("UNKNOWN");
                scan.setRiskScore(0);

            } else if (result.breached()) {

                int score =
                        calculateRiskScore(
                                result.breachCount());

                String severity =
                        calculateSeverity(score);

                scan.setStatus(
                        "EXPOSURE FOUND - "
                                + result.breachCount()
                                + " BREACHES");

                scan.setRisk(severity);
                scan.setRiskScore(score);

                createThreatIndicator(
                        target,
                        result.breachCount(),
                        severity);

            } else {

                scan.setStatus(
                        "NO EXPOSURE FOUND");

                scan.setRisk("LOW");
                scan.setRiskScore(0);
            }
        }

        // ==============================
        // DOMAIN
        // ==============================

        else if (looksLikeDomain(target)) {

            scan.setType("Domain");
            scan.setSource(
                    "DARKWATCH Domain Intelligence");

            DomainIntelligenceService.DomainResult result =
                    domainIntelligenceService.analyze(target);

            scan.setStatus(result.status());
            scan.setRisk(result.risk());
            scan.setRiskScore(
                    calculateDomainScore(result)
            );
        }

        // ==============================
        // USERNAME
        // ==============================

        else {

            scan.setType("Username");
            scan.setSource(
                    "GitHub Public Intelligence");

            UsernameIntelligenceService.UsernameResult result =
                    usernameIntelligenceService.analyze(target);

            scan.setStatus(result.status());
            scan.setRisk(result.risk());
            scan.setRiskScore(result.riskScore());
        }

        scanResultRepository.save(scan);

        return "redirect:/";
    }

    private boolean looksLikeDomain(String value) {

        return value.matches(
                ".*\\.[a-zA-Z]{2,}$"
        );
    }

    private int calculateDomainScore(
            DomainIntelligenceService.DomainResult result) {

        if (!result.valid()) {
            return 40;
        }

        if ("REACHABLE".equals(
                result.httpsStatus())) {
            return 15;
        }

        return 40;
    }

    private int calculateRiskScore(
            int breachCount) {

        if (breachCount >= 6) {
            return 90;
        }

        if (breachCount >= 4) {
            return 75;
        }

        if (breachCount >= 2) {
            return 55;
        }

        if (breachCount == 1) {
            return 30;
        }

        return 0;
    }

    private String calculateSeverity(
            int score) {

        if (score >= 90) {
            return "CRITICAL";
        }

        if (score >= 75) {
            return "HIGH";
        }

        if (score >= 50) {
            return "MEDIUM";
        }

        if (score > 0) {
            return "LOW";
        }

        return "UNKNOWN";
    }

    private void createThreatIndicator(
            String target,
            int breachCount,
            String severity) {

        String detectedAt =
                LocalDateTime.now().format(
                        DateTimeFormatter.ofPattern(
                                "yyyy-MM-dd HH:mm:ss"));

        ThreatIndicator indicator =
                new ThreatIndicator(
                        null,
                        "Have I Been Pwned",
                        "BREACH",
                        target
                                + " - "
                                + breachCount
                                + " breaches",
                        severity,
                        detectedAt);

        threatIndicatorRepository.save(
                indicator);
    }

    @GetMapping("/history")
    public String scanHistory(Model model) {

        model.addAttribute(
                "scanResults",
                scanResultRepository.findAll());

        return "scan-history";
    }

    @GetMapping("/alerts")
    public String threatAlerts(Model model) {

        List<ThreatIndicator> alerts =
                threatIndicatorRepository.findAll()
                        .stream()
                        .filter(indicator ->
                                "HIGH".equalsIgnoreCase(
                                        indicator.getSeverity())
                                        ||
                                "CRITICAL".equalsIgnoreCase(
                                        indicator.getSeverity())
                                        ||
                                "MEDIUM".equalsIgnoreCase(
                                        indicator.getSeverity()))
                        .collect(Collectors.toList());

        long highAlerts =
                alerts.stream()
                        .filter(indicator ->
                                "HIGH".equalsIgnoreCase(
                                        indicator.getSeverity())
                                        ||
                                "CRITICAL".equalsIgnoreCase(
                                        indicator.getSeverity()))
                        .count();

        long mediumAlerts =
                alerts.stream()
                        .filter(indicator ->
                                "MEDIUM".equalsIgnoreCase(
                                        indicator.getSeverity()))
                        .count();

        model.addAttribute("threatAlerts", alerts);
        model.addAttribute("highAlerts", highAlerts);
        model.addAttribute("mediumAlerts", mediumAlerts);

        return "threat-alerts";
    }

    @GetMapping("/tor-status")
    public String torStatus(Model model) {

        model.addAttribute(
                "torResponse",
                torService.checkTorConnection());

        return "tor-status";
    }

    @GetMapping("/monitoring")
    public String monitoring(Model model) {

        model.addAttribute(
                "sources",
                monitoredSourceRepository.findAll());

        return "monitoring";
    }

    @PostMapping("/monitoring/add")
    public String addSource(
            @RequestParam("name") String name,
            @RequestParam("onionAddress") String onionAddress,
            @RequestParam("category") String category) {

        if (name == null ||
                onionAddress == null ||
                name.isBlank() ||
                onionAddress.isBlank()) {

            return "redirect:/monitoring";
        }

        MonitoredSource source =
                new MonitoredSource(
                        name.trim(),
                        onionAddress.trim(),
                        category == null ||
                                category.isBlank()
                                ? "Intelligence"
                                : category.trim());

        monitoredSourceRepository.save(source);

        return "redirect:/monitoring";
    }

    @GetMapping("/monitoring/check/{id}")
    public String checkSource(
            @PathVariable Long id) {

        monitoredSourceRepository
                .findById(id)
                .ifPresent(
                        onionMonitoringService::checkSource);

        return "redirect:/monitoring";
    }

    @GetMapping("/monitoring/delete/{id}")
    public String deleteSource(
            @PathVariable Long id) {

        monitoredSourceRepository
                .deleteById(id);

        return "redirect:/monitoring";
    }

    @GetMapping("/intelligence")
    public String intelligence(Model model) {

        List<ThreatIndicator> indicators =
                threatIndicatorRepository.findAll();

        model.addAttribute("indicators", indicators);
        model.addAttribute(
                "totalIndicators",
                indicators.size());

        model.addAttribute(
                "highSeverity",
                indicators.stream()
                        .filter(i ->
                                "HIGH".equalsIgnoreCase(
                                        i.getSeverity())
                                        ||
                                "CRITICAL".equalsIgnoreCase(
                                        i.getSeverity()))
                        .count());

        model.addAttribute(
                "mediumSeverity",
                indicators.stream()
                        .filter(i ->
                                "MEDIUM".equalsIgnoreCase(
                                        i.getSeverity()))
                        .count());

        model.addAttribute(
                "lowSeverity",
                indicators.stream()
                        .filter(i ->
                                "LOW".equalsIgnoreCase(
                                        i.getSeverity()))
                        .count());

        return "intelligence";
    }

    @GetMapping("/reports")
    public String reports(Model model) {

        List<ScanResult> scans =
                scanResultRepository.findAll();

        ScanResult latestScan = null;

        if (!scans.isEmpty()) {
            latestScan =
                    scans.get(
                            scans.size() - 1);
        }

        model.addAttribute(
                "latestScan",
                latestScan);

        model.addAttribute(
                "totalScans",
                scans.size());

        return "reports";
    }

    @GetMapping("/reports/pdf")
    public ResponseEntity<byte[]>
    downloadLatestReport()
            throws Exception {

        List<ScanResult> scans =
                scanResultRepository.findAll();

        if (scans.isEmpty()) {

            return ResponseEntity
                    .noContent()
                    .build();
        }

        ScanResult latestScan =
                scans.get(
                        scans.size() - 1);

        byte[] pdf =
                pdfReportService
                        .generateReport(
                                latestScan);

        HttpHeaders headers =
                new HttpHeaders();

        headers.setContentType(
                MediaType.APPLICATION_PDF);

        headers.setContentDisposition(
                ContentDisposition
                        .attachment()
                        .filename(
                                "DARKWATCH_Report.pdf")
                        .build());

        headers.setContentLength(pdf.length);

        return ResponseEntity
                .ok()
                .headers(headers)
                .body(pdf);
    }
}
