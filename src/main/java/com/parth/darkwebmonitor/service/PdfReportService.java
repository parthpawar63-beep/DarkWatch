package com.parth.darkwebmonitor.service;

import com.parth.darkwebmonitor.model.ScanResult;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class PdfReportService {

    public byte[] generateReport(ScanResult scan)
            throws IOException {

        try (PDDocument document = new PDDocument();
             ByteArrayOutputStream output =
                     new ByteArrayOutputStream()) {

            PDPage page = new PDPage();
            document.addPage(page);

            PDType1Font titleFont =
                    new PDType1Font(
                            Standard14Fonts.FontName.HELVETICA_BOLD
                    );

            PDType1Font normalFont =
                    new PDType1Font(
                            Standard14Fonts.FontName.HELVETICA
                    );

            PDType1Font boldFont =
                    new PDType1Font(
                            Standard14Fonts.FontName.HELVETICA_BOLD
                    );

            try (PDPageContentStream content =
                         new PDPageContentStream(
                                 document,
                                 page
                         )) {

                float x = 60;
                float y = 740;

                // ==========================
                // TITLE
                // ==========================

                content.beginText();

                content.setFont(titleFont, 24);
                content.newLineAtOffset(x, y);

                content.showText(
                        "DARKWATCH SECURITY REPORT"
                );

                content.endText();


                y -= 40;


                content.beginText();

                content.setFont(normalFont, 11);
                content.newLineAtOffset(x, y);

                content.showText(
                        "Dark Web Exposure Monitoring and Threat Intelligence System"
                );

                content.endText();


                // ==========================
                // REPORT INFORMATION
                // ==========================

                y -= 55;

                drawLine(
                        content,
                        boldFont,
                        normalFont,
                        "Target",
                        safe(scan.getTarget()),
                        x,
                        y
                );

                y -= 25;

                drawLine(
                        content,
                        boldFont,
                        normalFont,
                        "Target Type",
                        safe(scan.getType()),
                        x,
                        y
                );

                y -= 25;

                drawLine(
                        content,
                        boldFont,
                        normalFont,
                        "Status",
                        safe(scan.getStatus()),
                        x,
                        y
                );

                y -= 25;

                drawLine(
                        content,
                        boldFont,
                        normalFont,
                        "Risk Level",
                        safe(scan.getRisk()),
                        x,
                        y
                );

                y -= 25;

                drawLine(
                        content,
                        boldFont,
                        normalFont,
                        "Risk Score",
                        scan.getRiskScore() + " / 100",
                        x,
                        y
                );

                y -= 25;

                drawLine(
                        content,
                        boldFont,
                        normalFont,
                        "Intelligence Source",
                        safe(scan.getSource()),
                        x,
                        y
                );

                y -= 25;

                String timestamp =
                        LocalDateTime.now().format(
                                DateTimeFormatter.ofPattern(
                                        "yyyy-MM-dd HH:mm:ss"
                                )
                        );

                drawLine(
                        content,
                        boldFont,
                        normalFont,
                        "Generated",
                        timestamp,
                        x,
                        y
                );


                // ==========================
                // RISK ASSESSMENT
                // ==========================

                y -= 55;

                content.beginText();

                content.setFont(
                        titleFont,
                        16
                );

                content.newLineAtOffset(x, y);

                content.showText(
                        "Risk Assessment"
                );

                content.endText();


                y -= 30;

                content.beginText();

                content.setFont(
                        normalFont,
                        11
                );

                content.newLineAtOffset(x, y);

                String recommendation =
                        getRecommendation(
                                scan.getRisk()
                        );

                content.showText(
                        recommendation
                );

                content.endText();


                // ==========================
                // METHODOLOGY
                // ==========================

                y -= 60;

                content.beginText();

                content.setFont(
                        titleFont,
                        16
                );

                content.newLineAtOffset(x, y);

                content.showText(
                        "Assessment Methodology"
                );

                content.endText();


                y -= 30;

                content.beginText();

                content.setFont(
                        normalFont,
                        10
                );

                content.newLineAtOffset(x, y);

                content.showText(
                        "DARKWATCH combines configured threat-intelligence"
                );

                content.newLineAtOffset(0, -16);

                content.showText(
                        "sources with an explainable risk-scoring model."
                );

                content.newLineAtOffset(0, -16);

                content.showText(
                        "Results should be validated before taking incident-response action."
                );

                content.endText();


                // ==========================
                // FOOTER
                // ==========================

                content.beginText();

                content.setFont(
                        normalFont,
                        9
                );

                content.newLineAtOffset(
                        60,
                        45
                );

                content.showText(
                        "DARKWATCH v1.0"
                );

                content.endText();
            }

            document.save(output);

            return output.toByteArray();
        }
    }


    private void drawLine(
            PDPageContentStream content,
            PDType1Font boldFont,
            PDType1Font normalFont,
            String label,
            String value,
            float x,
            float y)
            throws IOException {

        content.beginText();

        content.setFont(
                boldFont,
                11
        );

        content.newLineAtOffset(
                x,
                y
        );

        content.showText(
                label + ": "
        );

        content.setFont(
                normalFont,
                11
        );

        content.showText(
                value
        );

        content.endText();
    }


    private String getRecommendation(
            String risk) {

        if (risk == null) {
            return "Additional intelligence is required.";
        }

        return switch (risk.toUpperCase()) {

            case "CRITICAL" ->
                    "Immediate investigation, credential rotation, MFA and incident review are recommended.";

            case "HIGH" ->
                    "Investigate the exposure, review affected accounts and rotate potentially exposed credentials.";

            case "MEDIUM" ->
                    "Review the reported exposure and strengthen account security, including MFA.";

            case "LOW" ->
                    "Continue monitoring and maintain strong account security practices.";

            default ->
                    "Additional intelligence is required before a reliable risk assessment can be made.";
        };
    }


    private String safe(String value) {

        if (value == null || value.isBlank()) {
            return "Not available";
        }

        return value
                .replace("\n", " ")
                .replace("\r", " ");
    }
}
