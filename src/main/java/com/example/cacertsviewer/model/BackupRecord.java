package com.example.cacertsviewer.model;

import java.nio.file.Path;
import java.time.Instant;

public record BackupRecord(
        Path backupPath,
        Path originalPath,
        Instant createdAt,
        long size
) {
}
