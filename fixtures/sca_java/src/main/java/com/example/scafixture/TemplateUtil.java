package com.example.scafixture;

import java.util.Map;

import org.apache.commons.text.StringSubstitutor;

/**
 * Uses commons-text 1.9 outside any controller: the package is referenced,
 * but no entry point calls this helper. Fixture only; never deploy.
 */
final class TemplateUtil {

    private TemplateUtil() {
    }

    static String render(String template, Map<String, String> values) {
        return new StringSubstitutor(values).replace(template);
    }
}
