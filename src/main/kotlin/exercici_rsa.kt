import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher

const val ALGORITHM = "RSA"

fun main() {
    val keys = generateKeys()
    val public = keys.first
    val private = keys.second

    println("Hola benvingut al tutifruti el millor progrmaa per encriptar i desencrpitar missatges")
    println("Que vols fer encriptar o desencriptar un missatge?")



    while (true) {
        println("Si vols desencriptar escriu (1) si vols encriptar escriu (2), si vols deixar el programa (3) i si vols saber la teva clau publica (4)")
        val opcio = readln().toIntOrNull() ?: 0
        if (opcio == 1) {
            println("Escriu el misatge encriptat")
            val misatgeencriptat = readLine().toString()
            val desencriptar = (decrypt(misatgeencriptat, private))
            println("El teu missatge es el següent: $desencriptar")
        } else if (opcio == 2) {
            println("Escriu el teu missatge")
            val MisatgePerEncriptar = readLine().toString()
            val misatgeen = encrypt(MisatgePerEncriptar, public)
            println("El teu missatge encriptat a qeudat aixi: $misatgeen")
        } else if (opcio == 3) {
            break
        } else if (opcio == 4) {
            println("Aqui tens la teva clau publica: $public")
        } else if (opcio != 1 && opcio != 2 && opcio != 3 && opcio != 4){
            println("Opcio no valida posa un numero que estigui indicat")
        }
    }
    }



fun generateKeys(): Pair<String, String> {
    val keyGen = KeyPairGenerator.getInstance(ALGORITHM).apply {
        initialize(512)
    }

    // Key generation
    val keys = keyGen.genKeyPair()

    // Transformation to String (well encoded)
    val publicKeyString = Base64.getEncoder().encodeToString(keys.public.encoded)
    val privateKeyString = Base64.getEncoder().encodeToString(keys.private.encoded)

    return Pair(publicKeyString, privateKeyString)
}

fun encrypt(message: String, publicKey: String): String {
    // From a String, we obtain the Public Key
    val publicBytes = Base64.getDecoder().decode(publicKey)
    val decodedKey = KeyFactory.getInstance(ALGORITHM).generatePublic(X509EncodedKeySpec(publicBytes))

    // With the public, we encrypt the message
    val cipher = Cipher.getInstance(ALGORITHM).apply {
        init(Cipher.ENCRYPT_MODE, decodedKey)
    }
    val bytes = cipher.doFinal(message.encodeToByteArray())
    return String(Base64.getEncoder().encode(bytes))
}

fun decrypt(encryptedMessage: String, privateKey: String): String {
    // From a String, we obtain the Private Key
    val publicBytes = Base64.getDecoder().decode(privateKey)
    val decodedKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(PKCS8EncodedKeySpec(publicBytes))

    // Knowing the Private Key, we can decrypt the message
    val cipher = Cipher.getInstance(ALGORITHM).apply {
        init(Cipher.DECRYPT_MODE, decodedKey)
    }
    val bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage))
    return String(bytes)
}


