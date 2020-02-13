package org.acme.config

import io.smallrye.jwt.build.Jwt
import org.acme.data.UsersService
import org.acme.models.User
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jose4j.base64url.SimplePEMEncoder
import org.jose4j.jwt.JwtClaims
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import javax.inject.Singleton

@Singleton
class TokenHelper(private val usersSvc: UsersService) {
    @ConfigProperty(name = "privateKey")
    private var keyLocation: String = ""

    @ConfigProperty(name = "mp.jwt.verify.issuer")
    private var issuer: String = ""

    private fun setClaims(user: User): JwtClaims {

        var claims = JwtClaims()
        claims.issuer = issuer
        claims.setAudience(user.username)
        claims.setExpirationTimeMinutesInTheFuture(30f)
        claims.setGeneratedJwtId()
        claims.setIssuedAtToNow()
        claims.subject = user.username
        claims.setClaim("email", user.email)
        val roles = usersSvc.getUserGroups(user.username)
        claims.setStringListClaim("groups", roles)
        return claims
    }

    fun getToken(user: User): String {
        return generateToken(user)
    }

    private fun generateToken(user: User): String {
        return Jwt.claims(setClaims(user).claimsMap).issuer(issuer).sign(getPrivateKey())
    }

    private fun getPrivateKey(): PrivateKey {
        val keySpec = PKCS8EncodedKeySpec(SimplePEMEncoder.decode(getPemContent()))
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePrivate(keySpec)
    }

    private fun getPemContent(): String {
        return try {
            val result = Files.readAllLines(Path.of(keyLocation))
            result.drop(1).dropLast(1).toString().replace("\n\r", "").replace("\n", "")
        } catch (x: IOException) {
            // log error x.message!!
            ""
        }
    }
}