package com.parth.darkwebmonitor.repository;

import com.parth.darkwebmonitor.model.ScanResult;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {
}
