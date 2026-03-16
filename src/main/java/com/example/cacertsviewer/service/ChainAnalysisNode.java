package com.example.cacertsviewer.service;

import java.util.List;

public record ChainAnalysisNode(
        String alias,
        String subject,
        String role,
        List<String> badges
) {
}