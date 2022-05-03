package views.admin.programs;

import static com.google.common.base.Preconditions.checkNotNull;
import static j2html.TagCreator.div;
import static j2html.TagCreator.form;
import static j2html.TagCreator.h2;
import static j2html.TagCreator.p;

import com.github.slugify.Slugify;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.inject.Inject;
import j2html.tags.ContainerTag;
import play.mvc.Http.Request;
import play.twirl.api.Content;
import views.BaseHtmlView;
import views.HtmlBundle;
import views.admin.AdminLayout;
import views.components.FieldWithLabel;

/** Renders a page for adding a new ApiKey. */
public final class ApiKeyNewOneView extends BaseHtmlView {
  private final AdminLayout layout;

  @Inject
  public ApiKeyNewOneView(AdminLayout layout) {
    this.layout = checkNotNull(layout);
  }

  public Content render(Request request, ImmutableSet<String> programNames) {
    String title = "Create a new API key";

    ContainerTag formTag =
        form()
            .withMethod("POST")
            .with(
                makeCsrfTokenInputTag(request),
                FieldWithLabel.input().setFieldName("keyName").setLabelText("Name").getContainer(),
                FieldWithLabel.date()
                    .setFieldName("expiration")
                    .setLabelText("Expiration date")
                    .getContainer(),
                FieldWithLabel.input()
                    .setFieldName("subnet")
                    .setLabelText("Allowed subnet")
                    .getContainer());

    formTag.with(h2("Allowed programs"), p("Select the programs this key grants read access to."));

    Slugify slugifier = new Slugify();

    for (String name : programNames.stream().sorted().collect(ImmutableList.toImmutableList())) {
      formTag.with(
          FieldWithLabel.checkbox()
              .setFieldName(slugifier.slugify(name))
              .setLabelText(name)
              .getContainer());
    }

    ContainerTag contentDiv =
        div(
            formTag
                .with(submitButton("Save").withId("apikey-submit-button"))
                .withAction(controllers.admin.routes.AdminApiKeysController.create().url()));

    HtmlBundle htmlBundle =
        layout.getBundle().setTitle(title).addMainContent(renderHeader(title), contentDiv);

    return layout.renderCentered(htmlBundle);
  }
}
