package com.parth.darkwebmonitor.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class ThreatIndicator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long sourceId;
    private String sourceName;

    private String indicatorType;
    private String indicatorValue;

    private String severity;
    private String detectedAt;

    public ThreatIndicator() {
    }

    public ThreatIndicator(
            Long sourceId,
            String sourceName,
            String indicatorType,
            String indicatorValue,
            String severity,
            String detectedAt) {

        this.sourceId = sourceId;
        this.sourceName = sourceName;
        this.indicatorType = indicatorType;
        this.indicatorValue = indicatorValue;
        this.severity = severity;
        this.detectedAt = detectedAt;
    }

    public Long getId() {
        return id;
    }

    public Long getSourceId() {
        return sourceId;
    }

    public void setSourceId(Long sourceId) {
        this.sourceId = sourceId;
    }

    public String getSourceName() {
        return sourceName;
    }

    public void setSourceName(String sourceName) {
        this.sourceName = sourceName;
    }

    public String getIndicatorType() {
        return indicatorType;
    }

    public void setIndicatorType(String indicatorType) {
        this.indicatorType = indicatorType;
    }

    public String getIndicatorValue() {
        return indicatorValue;
    }

    public void setIndicatorValue(String indicatorValue) {
        this.indicatorValue = indicatorValue;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(String detectedAt) {
        this.detectedAt = detectedAt;
    }
}
