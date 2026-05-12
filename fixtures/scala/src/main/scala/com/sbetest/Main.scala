package com.sbetest

import cats.effect.{ExitCode, IO, IOApp}
import com.comcast.ip4s._
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits._

/** Entry point — runs the http4s ember server on localhost:8080. Never
  * actually started by the sbe tests (they only compile / test), but the
  * code path must type-check to prove cats-effect + ember + http4s
  * integrate cleanly under the sandbox.
  */
object Main extends IOApp {
  def run(args: List[String]): IO[ExitCode] =
    EmberServerBuilder
      .default[IO]
      .withHost(ipv4"0.0.0.0")
      .withPort(port"8080")
      .withHttpApp(HelloService.routes.orNotFound)
      .build
      .use(_ => IO.never)
      .as(ExitCode.Success)
}
