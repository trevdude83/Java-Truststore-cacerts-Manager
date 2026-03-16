package com.example.cacertsviewer.service;

import java.util.List;

public record ChainAnalysisResult(
        boolean trustedDirectly,
        boolean selfSigned,
        boolean certificateAuthority,
        boolean chainBuildComplete,
        boolean missingIssuer,
        String trustAnchorAlias,
        List<String> chainSubjects,
        List<String> diagnostics,
        List<ChainAnalysisNode> nodes
) {
}