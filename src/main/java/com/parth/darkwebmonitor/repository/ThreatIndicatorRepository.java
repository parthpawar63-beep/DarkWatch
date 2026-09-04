package com.parth.darkwebmonitor.repository;

import com.parth.darkwebmonitor.model.ThreatIndicator;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ThreatIndicatorRepository
        extends JpaRepository<ThreatIndicator, Long> {

    List<ThreatIndicator> findBySourceId(Long sourceId);

    long countBySeverity(String severity);
}
