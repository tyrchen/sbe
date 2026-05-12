package com.sbetest

import munit.CatsEffectSuite

final class GreeterSpec extends CatsEffectSuite {
  test("greet returns 'hello, <name>'") {
    Greeter.greet("sbe").map(assertEquals(_, "hello, sbe"))
  }
}
