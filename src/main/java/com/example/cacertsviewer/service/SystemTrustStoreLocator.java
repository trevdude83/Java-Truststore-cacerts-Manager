package com.example.cacertsviewer.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class SystemTrustStoreLocator {
    public Optional<Path> locateDefaultCacerts() {
        List<Path> candidates = new ArrayList<>();
        String javaHome = System.getProperty("java.home");
        if (javaHome != null && !javaHome.isBlank()) {
            Path home = Path.of(javaHome);
            candidates.add(home.resolve("lib").resolve("security").resolve("cacerts"));
            candidates.add(home.resolve("jre").resolve("lib").resolve("security").resolve("cacerts"));
            Path parent = home.getParent();
            if (parent != null) {
                candidates.add(parent.resolve("lib").resolve("security").resolve("cacerts"));
            }
        }

        return candidates.stream().filter(Files::exists).findFirst();
    }
}
