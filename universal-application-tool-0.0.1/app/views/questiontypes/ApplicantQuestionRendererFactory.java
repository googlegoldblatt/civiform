package views.questiontypes;

import services.applicant.ApplicantData;
import services.applicant.ApplicantQuestion;
import services.question.QuestionDefinition;
import services.question.QuestionDefinitionBuilder;
import services.question.QuestionType;
import services.question.UnsupportedQuestionTypeException;

public class ApplicantQuestionRendererFactory {

  public ApplicantQuestionRenderer getSampleRenderer(QuestionType questionType)
      throws UnsupportedQuestionTypeException {
    QuestionDefinition questionDefinition = QuestionDefinitionBuilder.sample(questionType).build();
    ApplicantQuestion applicantQuestion =
        new ApplicantQuestion(questionDefinition, new ApplicantData());
    return getRenderer(applicantQuestion);
  }

  public ApplicantQuestionRenderer getRenderer(ApplicantQuestion question) {
    switch (question.getType()) {
      case ADDRESS:
        return new AddressQuestionRenderer(question);
      case CHECKBOX:
        return new CheckboxQuestionRenderer(question);
      case DROPDOWN:
        return new DropdownQuestionRenderer(question);
      case NAME:
        return new NameQuestionRenderer(question);
      case NUMBER:
        return new NumberQuestionRenderer(question);
      case REPEATER:
        return new RepeaterQuestionRenderer(question);
      case TEXT:
        return new TextQuestionRenderer(question);
      default:
        throw new UnsupportedOperationException(
            "Unrecognized question type: " + question.getType());
    }
  }
}
