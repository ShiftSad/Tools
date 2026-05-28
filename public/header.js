// tools.shiftsad.dev — header (v3, plain)
(function () {
  const PAGES = [
    { href: "/dependency-extractor", label: "Dependências", key: "deps"  },
    { href: "/failmark",             label: "FailMark",     key: "fail"  },
    { href: "/virus-parcial",        label: "VirusParcial", key: "virus" },
  ];

  const current = document.documentElement.getAttribute("data-page") || "";

  const navHtml = PAGES.map(p => {
    const active = p.key === current ? ' aria-current="page"' : "";
    return `<a href="${p.href}"${active}>${p.label}</a>`;
  }).join("");

  const html = `
    <header class="site-header">
      <div class="site-header__inner">
        <a class="brand" href="/dependency-extractor"
           ><span class="brand__section">tools</span><span class="brand__domain">.shiftsad.dev</span></a>
        <nav class="nav" aria-label="Principal">${navHtml}</nav>
      </div>
    </header>
  `;
  document.addEventListener("DOMContentLoaded", () => {
    const slot = document.getElementById("site-header") || document.body;
    slot.insertAdjacentHTML("afterbegin", html);
  });
})();
