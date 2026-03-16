package com.example.cacertsviewer.service;

import com.example.cacertsviewer.model.TrustStoreDocument;

public record PasswordAwareLoadResult(TrustStoreDocument document, String detectedType) {
}
