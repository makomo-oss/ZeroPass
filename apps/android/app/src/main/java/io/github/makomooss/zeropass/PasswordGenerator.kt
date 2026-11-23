package io.github.makomooss.zeropass

import java.security.SecureRandom

/**
 * Random passwords from the system's random source, without bias: every
 * character is drawn uniformly ([SecureRandom.nextInt] rejects what would
 * skew), and each chosen kind of character appears at least once.
 */
object PasswordGenerator {
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!#\$%&()*+,-./:;<=>?@[]^_{|}~"
    private const val LOOK_ALIKE = "Il1O0o"

    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 128

    private val random = SecureRandom()

    data class Options(
        val length: Int = 20,
        val upper: Boolean = true,
        val digits: Boolean = true,
        val symbols: Boolean = true,
        val avoidLookAlike: Boolean = false,
    )

    private fun classes(options: Options): List<String> =
        listOfNotNull(
            LOWER,
            UPPER.takeIf { options.upper },
            DIGITS.takeIf { options.digits },
            SYMBOLS.takeIf { options.symbols },
        ).map { set -> if (options.avoidLookAlike) set.filterNot { it in LOOK_ALIKE } else set }

    fun generate(options: Options): String {
        val length = options.length.coerceIn(MIN_LENGTH, MAX_LENGTH)
        val classes = classes(options)
        val alphabet = classes.joinToString("")
        while (true) {
            val password = String(CharArray(length) { alphabet[random.nextInt(alphabet.length)] })
            if (classes.all { set -> password.any { it in set } }) return password
        }
    }

    /** The strength of passwords made with [options], in bits. */
    fun bits(options: Options): Int {
        val size = classes(options).sumOf { it.length }
        return (options.length.coerceIn(MIN_LENGTH, MAX_LENGTH) * Math.log(size.toDouble()) / Math.log(2.0)).toInt()
    }
}
