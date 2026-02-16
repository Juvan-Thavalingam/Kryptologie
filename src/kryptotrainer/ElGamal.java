package kryptotrainer;

import mybiginteger.*;

import java.util.Random;

/**
 * <p>Title: KryptoTrainer</p>
 * <p>Description: Übungsumgebung für das Wahlfach Kryptologie</p>
 * <p>Copyright: Copyright (c) 2006 / Samuel Beer</p>
 * <p>Company: Zürcher Hochschule Winterthur</p>
 * @author Samuel Beer
 * @version 1.0
 */

public class ElGamal {

  int bitLengthPublicKey;          // Länge der Primzahl p in Bits

  BigInteger[] publicKeyAlice;     // Öffentlicher Schlüssel (p,g,A) von Alice

  BigInteger privateKeyAlice;      // Privater Schlüssel a von Alice

  BigInteger plainText;            // Klartext Bob -> Alice

  BigInteger[] cipheredText;       // Chiffrat (B,c) Bob -> Alice

  BigInteger decipheredText;       // Dechiffrierter Text Bob -> Alice


  /************************************************************************
   ************************************************************************
   * Methoden, die ausprogrammiert werden müssen.
   ************************************************************************
   ************************************************************************/

  /**
   * Öffentlichen Schlüssel (p,g,A) und privaten Schlüssel (a) für Alice
   * generieren und in publicKeyAlice bzw. privateKeyAlice speichern.
   */
  public void generateKeyPair() {
    int certainty = 100;
    int smallPrimesUpperBound = 100000;
    Random rndSrc = new Random();
    BigInteger.createTableOfPrimes(smallPrimesUpperBound);
    BigInteger p = BigInteger.myProbableSafePrime(bitLengthPublicKey, certainty, rndSrc);
    BigInteger groupPOrder = p.subtract(BigInteger.ONE);
    BigInteger bigIntTwo = new BigInteger("2");
    BigInteger q = groupPOrder.divide(bigIntTwo);

    BigInteger g = BigInteger.ZERO;
    BigInteger twoDivTest = BigInteger.ZERO;
    BigInteger qDivTest = BigInteger.ZERO;
    do {
      g = new BigInteger(bitLengthPublicKey, rndSrc);

      twoDivTest = g.modPow(bigIntTwo, p);
      qDivTest = g.modPow(q, p);
    } while (twoDivTest.equals(BigInteger.ONE) || qDivTest.equals(BigInteger.ONE));

    BigInteger a = BigInteger.ONE;
    do {
      a = new BigInteger(bitLengthPublicKey, rndSrc);
    } while (a.equals(BigInteger.ZERO) || a.compareTo(groupPOrder) >= 0);
    BigInteger A = g.modPow(a, p);

    publicKeyAlice = new BigInteger[] { p, g, A };
    privateKeyAlice = a;
  }

  /**
   * Chiffrat (B,c) Bob -> Alice erstellen und in cipheredText abspeichern.
   */
  public void createCipheredText() {
    Random rndSrc = new Random();
    BigInteger b = BigInteger.ONE;
    do {
      b = new BigInteger(bitLengthPublicKey, rndSrc);
    } while (b.equals(BigInteger.ZERO) || b.compareTo(publicKeyAlice[0].subtract(BigInteger.ONE)) >= 0);

    BigInteger B = publicKeyAlice[1].modPow(b, publicKeyAlice[0]);
    BigInteger c = publicKeyAlice[2].modPow(b, publicKeyAlice[0]).multiply(plainText);
    cipheredText = new BigInteger[] { B, c };
  }

  /**
   * Dechiffrierten Text Bob -> Alice erstellen und in decipheredText abspeichern.
   */
  public void createDecipheredText() {
    BigInteger factor = cipheredText[0].modPow(publicKeyAlice[0].subtract(privateKeyAlice).subtract(BigInteger.ONE), publicKeyAlice[0]);
    decipheredText = cipheredText[1].multiply(factor).mod(publicKeyAlice[0]);
  }


  /************************************************************************
   ************************************************************************
   * Methoden, die fertig vorgegeben sind.
   ************************************************************************
   ************************************************************************/

  public ElGamal() {
  }

  public void setBitLength(int len) {
    bitLengthPublicKey = len;
  }

  public void setPlainText(BigInteger plain) {
    plainText = plain;
  }

  public BigInteger[] getCipheredText() {
    return cipheredText;
  }

  public BigInteger getDecipheredText() {
    return decipheredText;
  }

  public BigInteger[] getPublicKey() {
    return publicKeyAlice;
  }

  public BigInteger getPrivateKey() {
    return privateKeyAlice;
  }
}
