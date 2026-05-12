package com.sbetest

import cats.effect.IO

/** Small cats-effect helper — exists so the fixture exercises real
  * Scala compilation (cats-effect macros, IO type) under sbe, not just
  * build.sbt evaluation.
  */
object Greeter {
  def greet(name: String): IO[String] =
    IO.pure(s"hello, $name")
}
