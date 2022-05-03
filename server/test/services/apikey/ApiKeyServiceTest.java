package services.apikey;

import static org.assertj.core.api.Assertions.assertThat;
import static play.test.Helpers.fakeRequest;

import auth.ApiKeyGrants.Permission;
import auth.CiviFormProfile;
import auth.CiviFormProfileData;
import auth.ProfileFactory;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import models.ApiKey;
import org.junit.Before;
import org.junit.Test;
import play.data.DynamicForm;
import play.data.FormFactory;
import repository.ApiKeyRepository;
import repository.ResetPostgres;
import services.apikey.ApiKeyService.ApiKeyMutationResult;

public class ApiKeyServiceTest extends ResetPostgres {

  ApiKeyService apiKeyService;
  ApiKeyRepository apiKeyRepository;
  ProfileFactory profileFactory;
  CiviFormProfile adminProfile;

  @Before
  public void setUp() throws Exception {
    apiKeyService = instanceOf(ApiKeyService.class);
    apiKeyRepository = instanceOf(ApiKeyRepository.class);
    profileFactory = instanceOf(ProfileFactory.class);
    CiviFormProfileData profileData = profileFactory.createNewAdmin();
    adminProfile = profileFactory.wrapProfileData(profileData);
    adminProfile.setAuthorityId("authority-id").join();
  }

  @Test
  public void createApiKey_createsAnApiKey() {
    FormFactory formFactory = instanceOf(FormFactory.class);

    DynamicForm form =
        formFactory
            .form()
            .bindFromRequest(
                fakeRequest()
                    .bodyForm(
                        ImmutableMap.of(
                            "keyName", "test key",
                            "expiration", "2020-01-30",
                            "subnet", "0.0.0.1/32",
                            "grant-program-read[test-program]", "true"))
                    .build());

    ApiKeyMutationResult apiKeyMutationResult = apiKeyService.createApiKey(form, adminProfile);

    assertThat(apiKeyMutationResult.getForm().errors()).isEmpty();

    String credentialString = apiKeyMutationResult.getCredentials();
    byte[] keyIdBytes = Base64.getDecoder().decode(credentialString);
    String keyId =
        Iterables.get(Splitter.on(':').split(new String(keyIdBytes, StandardCharsets.UTF_8)), 0);
    ApiKey apiKey = apiKeyRepository.lookupApiKey(keyId).toCompletableFuture().join().get();

    assertThat(apiKey.getName()).isEqualTo("test key");
    assertThat(apiKey.getSubnet()).isEqualTo("0.0.0.1/32");
    assertThat(apiKey.getExpiration())
        .isEqualTo(
            LocalDate.parse("2020-01-30", DateTimeFormatter.ISO_DATE)
                .atStartOfDay()
                .toInstant(ZoneOffset.UTC));
    assertThat(apiKey.getGrants().hasProgramPermission("test-program", Permission.READ)).isTrue();
  }
}
