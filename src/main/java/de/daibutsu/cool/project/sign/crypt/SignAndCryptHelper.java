/*
 * Copyright 2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.daibutsu.cool.project.sign.crypt;

import static java.util.List.of;
import static org.bouncycastle.asn1.smime.SMIMECapability.dES_CBC;
import static org.bouncycastle.asn1.smime.SMIMECapability.dES_EDE3_CBC;
import static org.bouncycastle.asn1.smime.SMIMECapability.rC2_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.RC2_CBC;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;

public class SignAndCryptHelper {
	public MimeMessage signAndEncrypt(MimeMessage message, PrivateKey signPrivateKey, X509Certificate signCert,
			List<X509Certificate> encryptCert) throws Exception {
		message = sign(message, signPrivateKey, signCert);

		SMIMEEnvelopedGenerator encrypter = createSMIMEEnvelopedGenerator(encryptCert);
		MimeBodyPart mp = encrypter.generate(message, new JceCMSContentEncryptorBuilder(RC2_CBC).build());

		message.setContent(mp.getContent(), mp.getContentType());
		message.saveChanges();
		return message;
	}

	public MimeMessage sign(MimeMessage message, PrivateKey signPrivateKey, X509Certificate signCert) throws Exception {
		SMIMESignedGenerator signer = createSMIMESignedGenerator(signPrivateKey, signCert);
		MimeMultipart mm = signer.generate(message);
		message.setContent(mm, mm.getContentType());

		message.saveChanges();
		return message;
	}

	ASN1EncodableVector createASN1EncodableVector() {
		ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
		SMIMECapabilityVector caps = new SMIMECapabilityVector();

		caps.addCapability(dES_EDE3_CBC);
		caps.addCapability(rC2_CBC, 128);
		caps.addCapability(dES_CBC);

		signedAttrs.add(new SMIMECapabilitiesAttribute(caps));
		return signedAttrs;
	}

	SMIMESignedGenerator createSMIMESignedGenerator(PrivateKey signPrivateKey, X509Certificate signCert)
			throws GeneralSecurityException, OperatorCreationException {
		ASN1EncodableVector signedAttrs = createASN1EncodableVector();

		SMIMESignedGenerator gen = new SMIMESignedGenerator();
		gen.addSignerInfoGenerator(
				new JcaSimpleSignerInfoGeneratorBuilder().setSignedAttributeGenerator(new AttributeTable(signedAttrs))
						.build("SHA1withRSA", signPrivateKey, signCert));

		gen.addCertificates(new JcaCertStore(of(signCert)));
		return gen;
	}

	SMIMEEnvelopedGenerator createSMIMEEnvelopedGenerator(List<X509Certificate> recipientCert)
			throws GeneralSecurityException {
		SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();
		for (X509Certificate x509Certificate : recipientCert) {
			gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(x509Certificate));
		}
		return gen;
	}
}
