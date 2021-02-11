package services.question;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.collect.ImmutableMap;
import java.util.Locale;
import java.util.Optional;

/** Defines a single question. */
public class QuestionDefinition {
  private final String id;
  private final String version;
  private final String name;
  private final String path;
  private final String description;
  private final ImmutableMap<Locale, String> questionText;
  private final Optional<ImmutableMap<Locale, String>> questionHelpText;

  public QuestionDefinition(
      String id,
      String version,
      String name,
      String path,
      String description,
      ImmutableMap<Locale, String> questionText,
      Optional<ImmutableMap<Locale, String>> questionHelpText) {
    this.id = checkNotNull(id);
    this.version = checkNotNull(version);
    this.name = checkNotNull(name);
    this.path = checkNotNull(path);
    this.description = checkNotNull(description);
    this.questionText = checkNotNull(questionText);
    this.questionHelpText = questionHelpText;
  }

  /** Get the unique identifier for this question. */
  public String getId() {
    return this.id;
  }

  /** Get the system version this question is pinned to. */
  public String getVersion() {
    return this.version;
  }

  /**
   * Get the name of this question.
   *
   * <p>NOTE: This field will not be localized as it is for admin use only.
   */
  public String getName() {
    return this.name;
  }

  /** Get the full path of this question, in JSON notation. */
  public String getPath() {
    return this.path;
  }

  /**
   * Get a human-readable description for the data this question collects.
   *
   * <p>NOTE: This field will not be localized as it is for admin use only.
   */
  public String getDescription() {
    return this.description;
  }

  /** Get the question text for the given locale. */
  public String getQuestionText(Locale locale) {
    if (this.questionText.containsKey(locale)) {
      return this.questionText.get(locale);
    }

    throw new RuntimeException("Locale not found: " + locale);
  }

  /** Get the question help text for the given locale. */
  public String getQuestionHelpText(Locale locale) {
    if (!this.questionHelpText.isPresent()) {
      return "";
    }

    if (this.questionHelpText.get().containsKey(locale)) {
      return this.questionHelpText.get().get(locale);
    }

    throw new RuntimeException("Locale not found: " + locale);
  }

  /** Get the type of this question. */
  public QuestionType getQuestionType() {
    return QuestionType.TEXT;
  }

  /** Get a map of scalars stored by this question definition. */
  public ImmutableMap<String, ScalarType> getScalars() {
    return ImmutableMap.of("text", ScalarType.STRING);
  }

  public Optional<ScalarType> getScalarType(String key) {
    return Optional.ofNullable(this.getScalars().get(key));
  }
}