package uk.gov.ida.eidas.trustanchor.cli;

import com.nimbusds.jose.JOSEException;
import uk.gov.ida.eidas.trustanchor.Generator;

import java.io.*;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class Signer {
  private PrivateKey key;
  private X509Certificate certificate;
  private List<File> inputFiles;
  private File outputFile;

  Signer(PrivateKey key, X509Certificate certificate, List<File> inputFiles, File outputFile) {
    this.key = key;
    this.certificate = certificate;
    this.inputFiles = inputFiles;
    this.outputFile = outputFile;
  }

  public Void sign() throws IOException, JOSEException, ParseException, CertificateEncodingException {
    Collection<String> nonReadable = inputFiles.stream()
        .filter(f -> !f.canRead())
        .map(File::getPath)
        .collect(Collectors.toList());

    if (!nonReadable.isEmpty()) {
      String missingFiles = String.join(", ", nonReadable);
      throw new FileNotFoundException("Could not read files: " + missingFiles);
    }

    if (outputFile != null && !(outputFile.canWrite() || (!outputFile.exists() && outputFile.getAbsoluteFile().getParentFile().canWrite()))) {
      throw new FileNotFoundException("Cannot write to output file: " + outputFile.getAbsolutePath());
    }

    List<String> inputs = new ArrayList<>(inputFiles.size());
    for (File input : inputFiles) {
      inputs.add(new String(Files.readAllBytes(input.toPath())));
    }
    final Generator generator = new Generator(key, certificate);
    final String generatedAnchors = generator.generate(inputs).serialize();

    final OutputStreamWriter output = (outputFile == null ? new OutputStreamWriter(System.out) : new FileWriter(outputFile));
    output.write(generatedAnchors);
    output.close();

    return null;
  }
}
