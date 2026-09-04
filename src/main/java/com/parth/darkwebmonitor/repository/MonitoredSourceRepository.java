package com.parth.darkwebmonitor.repository;

import com.parth.darkwebmonitor.model.MonitoredSource;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MonitoredSourceRepository
        extends JpaRepository<MonitoredSource, Long> {
}
