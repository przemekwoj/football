package com.pw.football;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertTrue;


@SpringBootTest
class FootballApplicationTests {

	@Test
	void shouldFail() {
		assertTrue(true == false);
	}

	@Test
	void shouldPass(){
		assertTrue(true == true);

	}

}
