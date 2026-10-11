package com.example.vulnspring;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * One VULNERABLE endpoint and one SAFE counterpart per sink category
 * (command execution, dynamic evaluation, unsafe deserialization, path
 * traversal). SQL injection lives in {@link UserController}. Ground truth:
 * ground_truth.json. Fixture only; never deploy.
 */
@RestController
@RequestMapping("/api")
public class VulnerableController {

    private static final Path DATA_DIR = Path.of("data").toAbsolutePath().normalize();
    private static final Pattern HOST_RE = Pattern.compile("^[A-Za-z0-9.-]{1,253}$");
    private static final Pattern ARITHMETIC_RE = Pattern.compile("^\\s*(\\d+)\\s*([+-])\\s*(\\d+)\\s*$");
    private static final Map<String, Path> ALLOWED_FILES = Map.of("notes.txt", DATA_DIR.resolve("notes.txt"));

    // CWE-78 VULNERABLE: path variable concatenated into a shell command string.
    @GetMapping("/ping/{host}")
    public String ping(@PathVariable String host) throws IOException {
        String command = "ping -c 1 " + host;
        Process process = Runtime.getRuntime().exec(command);
        return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    // CWE-78 SAFE: allowlisted host, fixed argv, no shell.
    @GetMapping("/ping-safe/{host}")
    public String pingSafe(@PathVariable String host) throws IOException {
        if (!HOST_RE.matcher(host).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid host");
        }
        Process process = new ProcessBuilder("ping", "-c", "1", host).start();
        return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    // CWE-95 VULNERABLE: request body evaluated as a SpEL expression.
    @PostMapping("/calc")
    public Object calc(@RequestBody CalcRequest request) {
        return new SpelExpressionParser().parseExpression(request.expression()).getValue();
    }

    // CWE-95 SAFE: only "<int> <+|-> <int>" is parsed, nothing is evaluated.
    @PostMapping("/calc-safe")
    public long calcSafe(@RequestBody CalcRequest request) {
        var matcher = ARITHMETIC_RE.matcher(request.expression());
        if (!matcher.matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unsupported expression");
        }
        long left = Long.parseLong(matcher.group(1));
        long right = Long.parseLong(matcher.group(3));
        return "+".equals(matcher.group(2)) ? left + right : left - right;
    }

    // CWE-502 VULNERABLE: cookie bytes deserialized with ObjectInputStream.
    @GetMapping("/profile")
    public String profile(@CookieValue("profile") String profile) throws IOException, ClassNotFoundException {
        byte[] raw = Base64.getDecoder().decode(profile);
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(raw));
        Object value = in.readObject();
        return String.valueOf(value);
    }

    // CWE-502 SAFE: cookie is plain "name=<value>" text, never deserialized.
    @GetMapping("/profile-safe")
    public String profileSafe(@CookieValue("profile") String profile) {
        String decoded = new String(Base64.getDecoder().decode(profile), StandardCharsets.UTF_8);
        return decoded.startsWith("name=") ? decoded.substring(5) : "anonymous";
    }

    // CWE-22 VULNERABLE: query parameter resolved against the data dir unchecked.
    @GetMapping("/files")
    public String readFile(@RequestParam String name) throws IOException {
        return Files.readString(DATA_DIR.resolve(name));
    }

    // CWE-22 SAFE: only names from a fixed allowlist map to files.
    @GetMapping("/files-safe")
    public String readFileSafe(@RequestParam String name) throws IOException {
        Path target = ALLOWED_FILES.get(name);
        if (target == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown file");
        }
        return Files.readString(target);
    }
}
