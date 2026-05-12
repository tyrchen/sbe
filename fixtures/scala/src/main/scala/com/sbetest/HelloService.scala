package com.sbetest

import cats.effect.IO
import io.circe.generic.auto._
import org.http4s.HttpRoutes
import org.http4s.circe.CirceEntityCodec._
import org.http4s.dsl.io._

/** A small http4s service. The test is meant to compile under sbe, not to
  * serve real traffic — but the type signature exercises cats-effect IO,
  * http4s routing, and circe codecs in one go, so the build does meaningful
  * work for the sandbox to mediate.
  */
object HelloService {
  final case class Greeting(name: String, message: String)

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "hello" / name =>
      Ok(Greeting(name, s"hello, $name"))
  }
}
