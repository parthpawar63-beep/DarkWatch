package com.parth.darkwebmonitor.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class MonitoredSource {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String onionAddress;
    private String category;

    private String status;
    private long responseTime;
    private String lastChecked;

    private int httpStatus;
    private long contentLength;
    private int indicatorCount;
    private String riskLevel;

    public MonitoredSource() {
    }

    public MonitoredSource(
            String name,
            String onionAddress,
            String category) {

        this.name = name;
        this.onionAddress = onionAddress;
        this.category = category;

        this.status = "NOT CHECKED";
        this.responseTime = 0;
        this.lastChecked = "Never";

        this.httpStatus = 0;
        this.contentLength = 0;
        this.indicatorCount = 0;
        this.riskLevel = "UNKNOWN";
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getOnionAddress() {
        return onionAddress;
    }

    public void setOnionAddress(String onionAddress) {
        this.onionAddress = onionAddress;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public long getResponseTime() {
        return responseTime;
    }

    public void setResponseTime(long responseTime) {
        this.responseTime = responseTime;
    }

    public String getLastChecked() {
        return lastChecked;
    }

    public void setLastChecked(String lastChecked) {
        this.lastChecked = lastChecked;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(int httpStatus) {
        this.httpStatus = httpStatus;
    }

    public long getContentLength() {
        return contentLength;
    }

    public void setContentLength(long contentLength) {
        this.contentLength = contentLength;
    }

    public int getIndicatorCount() {
        return indicatorCount;
    }

    public void setIndicatorCount(int indicatorCount) {
        this.indicatorCount = indicatorCount;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }
}
