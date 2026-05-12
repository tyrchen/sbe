package com.sbetest

import cats.effect.IO
import io.circe.Json
import io.circe.parser._
import munit.CatsEffectSuite
import org.http4s.{Method, Request, Status, Uri}
import org.http4s.implicits._

final class HelloServiceSpec extends CatsEffectSuite {
  test("GET /hello/<name> returns a JSON greeting") {
    val req = Request[IO](Method.GET, uri"/hello/sbe")
    HelloService.routes.orNotFound.run(req).flatMap { resp =>
      assertEquals(resp.status, Status.Ok)
      resp.as[String].map { body =>
        val parsed = parse(body).getOrElse(Json.Null)
        assertEquals(parsed.hcursor.get[String]("name").toOption, Some("sbe"))
      }
    }
  }
}
