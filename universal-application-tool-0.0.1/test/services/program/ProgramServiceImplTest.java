package services.program;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import forms.BlockForm;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import org.junit.Before;
import org.junit.Test;
import repository.WithPostgresContainer;
import services.Path;
import services.question.AddressQuestionDefinition;
import services.question.NameQuestionDefinition;
import services.question.QuestionDefinition;
import services.question.QuestionNotFoundException;
import services.question.QuestionService;
import services.question.TextQuestionDefinition;

public class ProgramServiceImplTest extends WithPostgresContainer {

  private static final QuestionDefinition SIMPLE_QUESTION =
      new NameQuestionDefinition(
          2L,
          "Name Question",
          Path.create("applicant.name"),
          "The name of the applicant.",
          ImmutableMap.of(Locale.US, "What is your name?"),
          ImmutableMap.of());
  private ProgramServiceImpl ps;
  private QuestionService qs;

  @Before
  public void setProgramServiceImpl() {
    ps = instanceOf(ProgramServiceImpl.class);
    qs = instanceOf(QuestionService.class);
  }

  @Test
  public void listProgramDefinitions_hasNoResults() {
    ImmutableList<ProgramDefinition> programDefinitions = ps.listProgramDefinitions();

    assertThat(programDefinitions).isEmpty();
  }

  @Test
  public void listProgramDefinitions_hasResults() {
    ProgramDefinition first = ps.createProgramDefinition("first name", "first description");
    ProgramDefinition second = ps.createProgramDefinition("second name", "second description");

    ImmutableList<ProgramDefinition> programDefinitions = ps.listProgramDefinitions();

    assertThat(programDefinitions).containsExactly(first, second);
  }

  @Test
  public void listProgramDefinitions_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition program = ps.createProgramDefinition("Program Name", "Program Description");
    ps.addQuestionsToBlock(program.id(), 1L, ImmutableList.of(question.getId()));

    ImmutableList<ProgramDefinition> programDefinitions = ps.listProgramDefinitions();

    QuestionDefinition foundQuestion =
        programDefinitions
            .get(0)
            .blockDefinitions()
            .get(0)
            .programQuestionDefinitions()
            .get(0)
            .getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void listProgramDefinitionsAsync_hasNoResults() {
    CompletionStage<ImmutableList<ProgramDefinition>> completionStage =
        ps.listProgramDefinitionsAsync();

    assertThat(completionStage.toCompletableFuture().join()).isEmpty();
  }

  @Test
  public void listProgramDefinitionsAsync_hasResults() {
    ProgramDefinition first = ps.createProgramDefinition("first name", "first description");
    ProgramDefinition second = ps.createProgramDefinition("second name", "second description");

    CompletionStage<ImmutableList<ProgramDefinition>> completionStage =
        ps.listProgramDefinitionsAsync();

    assertThat(completionStage.toCompletableFuture().join()).containsExactly(first, second);
  }

  @Test
  public void listProgramDefinitionsAsync_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition program = ps.createProgramDefinition("Program Name", "Program Description");
    ps.addQuestionsToBlock(program.id(), 1L, ImmutableList.of(question.getId()));

    ImmutableList<ProgramDefinition> programDefinitions =
        ps.listProgramDefinitionsAsync().toCompletableFuture().join();

    QuestionDefinition foundQuestion =
        programDefinitions
            .get(0)
            .blockDefinitions()
            .get(0)
            .programQuestionDefinitions()
            .get(0)
            .getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void syncQuestions_constructsAllQuestionDefinitions() throws Exception {
    QuestionDefinition questionOne = qs.create(SIMPLE_QUESTION).getResult();
    QuestionDefinition questionTwo =
        qs.create(
                new AddressQuestionDefinition(
                    3L,
                    "Applicant Address",
                    Path.create("applicant.address"),
                    "Applicant's address",
                    ImmutableMap.of(Locale.US, "What is your addess?"),
                    ImmutableMap.of()))
            .getResult();
    QuestionDefinition questionThree =
        qs.create(
                new TextQuestionDefinition(
                    3L,
                    "Favorite color",
                    Path.create("applicant.favcolor"),
                    "Applicant's favorite color",
                    ImmutableMap.of(Locale.US, "Is orange your favorite color?"),
                    ImmutableMap.of()))
            .getResult();

    ProgramDefinition programOne =
        ps.createProgramDefinition("Program One", "Program One Description");
    ps.addQuestionsToBlock(
        programOne.id(), 1L, ImmutableList.of(questionOne.getId(), questionTwo.getId()));
    ps.addBlockToProgram(
        programOne.id(),
        "Block Two",
        "Block Two Description",
        ImmutableList.of(ProgramQuestionDefinition.create(questionThree.getId())));

    ProgramDefinition programTwo =
        ps.createProgramDefinition("Program Two", "Program Two Description");
    ps.addQuestionsToBlock(programTwo.id(), 1L, ImmutableList.of(questionTwo.getId()));
    ps.addBlockToProgram(
        programTwo.id(),
        "Block Two",
        "Block Two Description",
        ImmutableList.of(ProgramQuestionDefinition.create(questionOne.getId())));

    ImmutableList<ProgramDefinition> programDefinitions = ps.listProgramDefinitions();

    QuestionDefinition found = programDefinitions.get(0).getQuestionDefinition(0, 0);
    assertThat(found).isInstanceOf(NameQuestionDefinition.class);
    found = programDefinitions.get(0).getQuestionDefinition(0, 1);
    assertThat(found).isInstanceOf(AddressQuestionDefinition.class);
    found = programDefinitions.get(0).getQuestionDefinition(1, 0);
    assertThat(found).isInstanceOf(TextQuestionDefinition.class);
    found = programDefinitions.get(1).getQuestionDefinition(0, 0);
    assertThat(found).isInstanceOf(AddressQuestionDefinition.class);
    found = programDefinitions.get(1).getQuestionDefinition(1, 0);
    assertThat(found).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void createProgram_setsId() {
    assertThat(ps.listProgramDefinitions()).isEmpty();

    ProgramDefinition programDefinition =
        ps.createProgramDefinition("ProgramService", "description");

    assertThat(programDefinition.id()).isNotNull();
  }

  @Test
  public void createProgram_hasEmptyBlock() {
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("ProgramService", "description");

    assertThat(programDefinition.blockDefinitions()).hasSize(1);
    assertThat(programDefinition.getBlockDefinition(0).get().id()).isEqualTo(1L);
    assertThat(programDefinition.getBlockDefinition(0).get().name()).isEqualTo("Block 1");
  }

  @Test
  public void updateProgram_withNoProgram_throwsProgramNotFoundException() {
    assertThatThrownBy(() -> ps.updateProgramDefinition(1L, "new", "new description"))
        .isInstanceOf(ProgramNotFoundException.class)
        .hasMessage("Program not found for ID: 1");
  }

  @Test
  public void updateProgram_updatesProgram() throws Exception {
    ProgramDefinition originalProgram =
        ps.createProgramDefinition("original", "original description");
    ProgramDefinition updatedProgram =
        ps.updateProgramDefinition(originalProgram.id(), "new", "new description");

    Optional<ProgramDefinition> found = ps.getProgramDefinition(updatedProgram.id());

    assertThat(ps.listProgramDefinitions()).hasSize(1);
    assertThat(found).hasValue(updatedProgram);
  }

  @Test
  public void updateProgram_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition program = ps.createProgramDefinition("Program Name", "Program Description");
    ps.addQuestionsToBlock(program.id(), 1L, ImmutableList.of(question.getId()));

    ProgramDefinition found =
        ps.updateProgramDefinition(program.id(), "new name", "new description");

    QuestionDefinition foundQuestion =
        found.blockDefinitions().get(0).programQuestionDefinitions().get(0).getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void getProgramDefinition_canGetANewProgram() {
    ProgramDefinition programDefinition = ps.createProgramDefinition("new program", "description");
    Optional<ProgramDefinition> found = ps.getProgramDefinition(programDefinition.id());

    assertThat(found).hasValue(programDefinition);
  }

  @Test
  public void getProgramDefinition_returnsEmptyOptionalWhenProgramNotFound() {
    ProgramDefinition programDefinition = ps.createProgramDefinition("new program", "description");
    Optional<ProgramDefinition> found = ps.getProgramDefinition(programDefinition.id() + 1);

    assertThat(found).isEmpty();
  }

  @Test
  public void getProgramDefinition_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition program = ps.createProgramDefinition("Program Name", "Program Description");
    ps.addQuestionsToBlock(program.id(), 1L, ImmutableList.of(question.getId()));

    ProgramDefinition found = ps.getProgramDefinition(program.id()).get();

    QuestionDefinition foundQuestion =
        found.blockDefinitions().get(0).programQuestionDefinitions().get(0).getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void getProgramDefinitionAsync_getsRequestedProgram() {
    ProgramDefinition programDefinition = ps.createProgramDefinition("async", "program");

    CompletionStage<Optional<ProgramDefinition>> found =
        ps.getProgramDefinitionAsync(programDefinition.id());

    assertThat(found.toCompletableFuture().join()).hasValue(programDefinition);
  }

  @Test
  public void getProgramDefinitionAsync_cannotFindRequestedProgram_returnsEmptyOptional() {
    ProgramDefinition programDefinition = ps.createProgramDefinition("different", "program");

    CompletionStage<Optional<ProgramDefinition>> found =
        ps.getProgramDefinitionAsync(programDefinition.id() + 1);

    assertThat(found.toCompletableFuture().join()).isEmpty();
  }

  @Test
  public void getProgramDefinitionAsync_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition program = ps.createProgramDefinition("Program Name", "Program Description");
    ps.addQuestionsToBlock(program.id(), 1L, ImmutableList.of(question.getId()));

    ProgramDefinition found =
        ps.getProgramDefinitionAsync(program.id()).toCompletableFuture().join().get();

    QuestionDefinition foundQuestion =
        found.blockDefinitions().get(0).programQuestionDefinitions().get(0).getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void addBlockToProgram_noProgram_throwsProgramNotFoundException() {
    assertThatThrownBy(() -> ps.addBlockToProgram(1L))
        .isInstanceOf(ProgramNotFoundException.class)
        .hasMessage("Program not found for ID: 1");

    assertThatThrownBy(() -> ps.addBlockToProgram(1L, "name", "desc"))
        .isInstanceOf(ProgramNotFoundException.class)
        .hasMessage("Program not found for ID: 1");

    assertThatThrownBy(() -> ps.addBlockToProgram(1L, "name", "description", ImmutableList.of()))
        .isInstanceOf(ProgramNotFoundException.class)
        .hasMessage("Program not found for ID: 1");
  }

  @Test
  public void addBlockToProgram_emptyBlock_returnsProgramDefinitionWithBlock() throws Exception {
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Block", "This program has a block.");
    Long programId = programDefinition.id();
    ProgramDefinition updatedProgramDefinition = ps.addBlockToProgram(programDefinition.id());

    ProgramDefinition found = ps.getProgramDefinition(programId).orElseThrow();

    assertThat(found.blockDefinitions()).hasSize(2);
    assertThat(found.blockDefinitions())
        .containsExactlyElementsOf(updatedProgramDefinition.blockDefinitions());

    BlockDefinition emptyBlock = found.blockDefinitions().get(0);
    assertThat(emptyBlock.name()).isEqualTo("Block 1");
    assertThat(emptyBlock.description()).isEqualTo("");
    assertThat(emptyBlock.programQuestionDefinitions()).hasSize(0);

    BlockDefinition newBlock = found.blockDefinitions().get(1);
    assertThat(newBlock.name()).isEqualTo("Block 2");
    assertThat(newBlock.description()).isEqualTo("");
    assertThat(newBlock.programQuestionDefinitions()).hasSize(0);
  }

  @Test
  public void addBlockToProgram_returnsProgramDefinitionWithBlock() throws Exception {
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Block", "This program has a block.");
    Long programId = programDefinition.id();
    ProgramDefinition updatedProgramDefinition =
        ps.addBlockToProgram(programDefinition.id(), "the block", "the block for the program");

    ProgramDefinition found = ps.getProgramDefinition(programId).orElseThrow();

    assertThat(found.blockDefinitions()).hasSize(2);
    assertThat(found.blockDefinitions())
        .containsExactlyElementsOf(updatedProgramDefinition.blockDefinitions());

    BlockDefinition emptyBlock = found.blockDefinitions().get(0);
    assertThat(emptyBlock.name()).isEqualTo("Block 1");
    assertThat(emptyBlock.description()).isEqualTo("");
    assertThat(emptyBlock.programQuestionDefinitions()).hasSize(0);

    BlockDefinition newBlock = found.blockDefinitions().get(1);
    assertThat(newBlock.name()).isEqualTo("the block");
    assertThat(newBlock.description()).isEqualTo("the block for the program");
    assertThat(newBlock.programQuestionDefinitions()).hasSize(0);
  }

  @Test
  public void addBlockToProgram_WithQuestions_returnsProgramDefinitionWithBlock() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition programDefinition = ps.createProgramDefinition("program", "description");
    long id = programDefinition.id();
    ProgramQuestionDefinition programQuestionDefinition =
        ProgramQuestionDefinition.create(question);

    ProgramDefinition updated =
        ps.addBlockToProgram(id, "block", "desc", ImmutableList.of(programQuestionDefinition));

    assertThat(updated.blockDefinitions()).hasSize(2);

    BlockDefinition emptyBlock = updated.blockDefinitions().get(0);
    assertThat(emptyBlock.name()).isEqualTo("Block 1");
    assertThat(emptyBlock.description()).isEqualTo("");
    assertThat(emptyBlock.programQuestionDefinitions()).hasSize(0);

    BlockDefinition newBlock = updated.blockDefinitions().get(1);
    assertThat(newBlock.id()).isEqualTo(2L);
    assertThat(newBlock.name()).isEqualTo("block");
    assertThat(newBlock.description()).isEqualTo("desc");

    assertThat(newBlock.programQuestionDefinitions()).hasSize(1);
    ProgramQuestionDefinition foundPqd = newBlock.programQuestionDefinitions().get(0);

    assertThat(foundPqd.id()).isEqualTo(programQuestionDefinition.id());
    assertThat(foundPqd.getQuestionDefinition()).isInstanceOf(NameQuestionDefinition.class);
    assertThat(foundPqd.getQuestionDefinition().getName()).isEqualTo("Name Question");
  }

  @Test
  public void addBlockToProgram_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition program = ps.createProgramDefinition("Program Name", "Program Description");

    program =
        ps.addBlockToProgram(
            program.id(),
            "Block",
            "Block Description",
            ImmutableList.of(ProgramQuestionDefinition.create(question)));

    QuestionDefinition foundQuestion =
        program
            .blockDefinitions()
            .get(1)
            .programQuestionDefinitions()
            .get(0)
            .getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);

    program = ps.addBlockToProgram(program.id(), "empty block", "this block has no questions");

    foundQuestion =
        program
            .blockDefinitions()
            .get(1)
            .programQuestionDefinitions()
            .get(0)
            .getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void updateBlock_noProgram_throwsProgramNotFoundException() {
    assertThatThrownBy(() -> ps.updateBlock(1L, 1L, new BlockForm()))
        .isInstanceOf(ProgramNotFoundException.class)
        .hasMessage("Program not found for ID: 1");
  }

  @Test
  public void updateBlock() throws Exception {
    ProgramDefinition program = ps.createProgramDefinition("Program", "description");

    BlockForm blockForm = new BlockForm();
    blockForm.setName("new block name");
    blockForm.setDescription("new description");

    ps.updateBlock(program.id(), 1L, blockForm);

    ProgramDefinition found = ps.getProgramDefinition(program.id()).orElseThrow();

    assertThat(found.blockDefinitions()).hasSize(1);
    assertThat(found.getBlockDefinition(1L).get().name()).isEqualTo("new block name");
    assertThat(found.getBlockDefinition(1L).get().description()).isEqualTo("new description");
  }

  @Test
  public void setBlockQuestions_updatesBlock() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();

    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Block", "This program has a block.");
    Long programId = programDefinition.id();
    ps.setBlockQuestions(
        programId, 1L, ImmutableList.of(ProgramQuestionDefinition.create(question)));

    ProgramDefinition found = ps.getProgramDefinition(programId).orElseThrow();
    assertThat(found.blockDefinitions()).hasSize(1);

    BlockDefinition foundBlock = found.blockDefinitions().get(0);
    assertThat(foundBlock.programQuestionDefinitions()).hasSize(1);

    ProgramQuestionDefinition foundPqd =
        found.blockDefinitions().get(0).programQuestionDefinitions().get(0);
    assertThat(foundPqd.id()).isEqualTo(question.getId());
    assertThat(foundPqd.getQuestionDefinition()).isInstanceOf(NameQuestionDefinition.class);
    assertThat(foundPqd.getQuestionDefinition().getName()).isEqualTo("Name Question");
  }

  @Test
  public void setBlockQuestions_withBogusBlockId_throwsProgramBlockNotFoundException() {
    ProgramDefinition p = ps.createProgramDefinition("name", "description");
    assertThatThrownBy(() -> ps.setBlockQuestions(p.id(), 100L, ImmutableList.of()))
        .isInstanceOf(ProgramBlockNotFoundException.class)
        .hasMessage(String.format("Block not found in Program (ID %d) for block ID 100", p.id()));
  }

  @Test
  public void setBlockQuestions_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Block", "This program has a block.");
    Long programId = programDefinition.id();
    ps.addBlockToProgram(programId, "the block", "the block for the program");

    ProgramDefinition found =
        ps.setBlockQuestions(
            programId, 1L, ImmutableList.of(ProgramQuestionDefinition.create(question)));
    QuestionDefinition foundQuestion =
        found.blockDefinitions().get(0).programQuestionDefinitions().get(0).getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void addQuestionsToBlock_withDuplicatedQuestions_throwsDuplicateProgramQuestionException()
      throws Exception {
    QuestionDefinition questionA =
        resourceCreator().insertQuestion("applicant.questionA").getQuestionDefinition();

    BlockDefinition block =
        BlockDefinition.builder()
            .setId(1L)
            .setName("block 1")
            .setDescription("block the first")
            .addQuestion(ProgramQuestionDefinition.create(questionA))
            .build();

    ProgramDefinition program =
        resourceCreator().insertProgram("test program", block).getProgramDefinition();

    assertThatThrownBy(
            () ->
                ps.addQuestionsToBlock(
                    program.id(), block.id(), ImmutableList.of(questionA.getId())))
        .isInstanceOf(DuplicateProgramQuestionException.class)
        .hasMessage(
            String.format(
                "Question (ID %d) already exists in Program (ID %d)",
                questionA.getId(), program.id()));
    ;
  }

  @Test
  public void addQuestionsToBlock_addsQuestionsToTheBlock() throws Exception {
    QuestionDefinition questionA =
        resourceCreator().insertQuestion("applicant.questionA").getQuestionDefinition();
    QuestionDefinition questionB =
        resourceCreator().insertQuestion("applicant.questionB").getQuestionDefinition();

    BlockDefinition block =
        BlockDefinition.builder()
            .setId(1L)
            .setName("block 1")
            .setDescription("block the first")
            .addQuestion(ProgramQuestionDefinition.create(questionA))
            .build();

    ProgramDefinition program =
        resourceCreator().insertProgram("test program", block).getProgramDefinition();

    program = ps.addQuestionsToBlock(program.id(), block.id(), ImmutableList.of(questionB.getId()));

    assertThat(program.hasQuestion(questionA)).isTrue();
    assertThat(program.hasQuestion(questionB)).isTrue();
  }

  @Test
  public void removeQuestionsFromBlock_withoutQuestion_throwsQuestionNotFoundException()
      throws Exception {
    QuestionDefinition questionA =
        resourceCreator().insertQuestion("applicant.questionA").getQuestionDefinition();

    BlockDefinition block =
        BlockDefinition.builder()
            .setId(1L)
            .setName("block 1")
            .setDescription("block the first")
            .build();

    ProgramDefinition program =
        resourceCreator().insertProgram("test program", block).getProgramDefinition();

    assertThatThrownBy(
            () ->
                ps.removeQuestionsFromBlock(
                    program.id(), block.id(), ImmutableList.of(questionA.getId())))
        .isInstanceOf(QuestionNotFoundException.class)
        .hasMessage(
            String.format(
                "Question (ID %d) not found in Program (ID %d)", questionA.getId(), program.id()));
    ;
  }

  @Test
  public void removeQuestionsFromBlock_removesQuestionsFromTheBlock() throws Exception {
    QuestionDefinition questionA =
        resourceCreator().insertQuestion("applicant.questionA").getQuestionDefinition();
    QuestionDefinition questionB =
        resourceCreator().insertQuestion("applicant.questionB").getQuestionDefinition();

    BlockDefinition block =
        BlockDefinition.builder()
            .setId(1L)
            .setName("block 1")
            .setDescription("block the first")
            .addQuestion(ProgramQuestionDefinition.create(questionA))
            .addQuestion(ProgramQuestionDefinition.create(questionB))
            .build();

    ProgramDefinition program =
        resourceCreator().insertProgram("test program", block).getProgramDefinition();

    program =
        ps.removeQuestionsFromBlock(program.id(), block.id(), ImmutableList.of(questionB.getId()));

    assertThat(program.hasQuestion(questionA)).isTrue();
    assertThat(program.hasQuestion(questionB)).isFalse();
  }

  @Test
  public void setBlockHidePredicate_updatesBlock() throws Exception {
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Block", "This program has a block.");
    Long programId = programDefinition.id();
    ps.addBlockToProgram(programId, "the block", "the block for the program");
    Predicate predicate = Predicate.create("hide predicate");
    ps.setBlockHidePredicate(programId, 1L, predicate);

    ProgramDefinition found = ps.getProgramDefinition(programId).orElseThrow();

    assertThat(found.blockDefinitions().get(0).hidePredicate()).hasValue(predicate);
  }

  @Test
  public void setBlockHidePredicate_withBogusBlockId_throwsProgramBlockNotFoundException() {
    ProgramDefinition p = ps.createProgramDefinition("name", "description");
    assertThatThrownBy(() -> ps.setBlockHidePredicate(p.id(), 100L, Predicate.create("")))
        .isInstanceOf(ProgramBlockNotFoundException.class)
        .hasMessage(String.format("Block not found in Program (ID %d) for block ID 100", p.id()));
  }

  @Test
  public void setBlockHidePredicate_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Block", "This program has a block.");
    Long programId = programDefinition.id();
    ps.addBlockToProgram(
        programId,
        "the block",
        "the block for the program",
        ImmutableList.of(ProgramQuestionDefinition.create(question)));

    ProgramDefinition found =
        ps.setBlockHidePredicate(programId, 2L, Predicate.create("predicate"));

    QuestionDefinition foundQuestion =
        found.blockDefinitions().get(1).programQuestionDefinitions().get(0).getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void setBlockOptionalPredicate_updatesBlock() throws Exception {
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Block", "This program has a block.");
    Long programId = programDefinition.id();
    ps.addBlockToProgram(programId, "the block", "the block for the program");
    Predicate predicate = Predicate.create("hide predicate");
    ps.setBlockOptionalPredicate(programId, 1L, predicate);

    ProgramDefinition found = ps.getProgramDefinition(programId).orElseThrow();

    assertThat(found.blockDefinitions().get(0).optionalPredicate()).hasValue(predicate);
  }

  @Test
  public void setBlockOptionalPredicate_withBogusBlockId_throwsProgramBlockNotFoundException() {
    ProgramDefinition p = ps.createProgramDefinition("name", "description");
    assertThatThrownBy(() -> ps.setBlockOptionalPredicate(p.id(), 100L, Predicate.create("")))
        .isInstanceOf(ProgramBlockNotFoundException.class)
        .hasMessage(String.format("Block not found in Program (ID %d) for block ID 100", p.id()));
  }

  @Test
  public void setBlockOptionalPredicate_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Block", "This program has a block.");
    Long programId = programDefinition.id();
    ps.addQuestionsToBlock(programId, 1L, ImmutableList.of(question.getId()));

    ProgramDefinition found =
        ps.setBlockOptionalPredicate(programId, 1L, Predicate.create("predicate"));
    QuestionDefinition foundQuestion =
        found.blockDefinitions().get(0).programQuestionDefinitions().get(0).getQuestionDefinition();
    assertThat(foundQuestion).isInstanceOf(NameQuestionDefinition.class);
  }

  @Test
  public void deleteBlock_invalidProgram_throwsProgramNotfoundException() {
    assertThatThrownBy(() -> ps.deleteBlock(1L, 2L))
        .isInstanceOf(ProgramNotFoundException.class)
        .hasMessage("Program not found for ID: 1");
  }

  @Test
  public void deleteBlock_lastBlock_throwsProgramNeedsABlockException() throws Exception {
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Empty Block", "This program has a block.");
    Long programId = programDefinition.id();

    assertThatThrownBy(() -> ps.deleteBlock(programId, 1L))
        .isInstanceOf(ProgramNeedsABlockException.class);
  }

  @Test
  public void deleteBlock_constructsQuestionDefinitions() throws Exception {
    QuestionDefinition question = qs.create(SIMPLE_QUESTION).getResult();
    ProgramDefinition programDefinition =
        ps.createProgramDefinition("Program With Block", "This program has a block.");
    Long programId = programDefinition.id();
    ps.addBlockToProgram(
        programId,
        "the second block",
        "the second block for the program",
        ImmutableList.of(ProgramQuestionDefinition.create(question)));

    ProgramDefinition result = ps.deleteBlock(programId, 1L);

    assertThat(result.blockDefinitions()).hasSize(1);

    BlockDefinition blockResult = result.blockDefinitions().get(0);
    assertThat(blockResult.name()).isEqualTo("the second block");
    assertThat(blockResult.programQuestionDefinitions()).hasSize(1);

    QuestionDefinition questionResult =
        blockResult.programQuestionDefinitions().get(0).getQuestionDefinition();
    assertThat(questionResult).isInstanceOf(NameQuestionDefinition.class);
  }
}