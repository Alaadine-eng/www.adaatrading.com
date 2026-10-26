// functions/form-handler.js

export const onRequestPost = async (context) => {
  try {
    // ============================================================
    // 1. PARSE FORM DATA
    // ============================================================
    const formData = await context.request.formData();

    const fullName     = (formData.get("name")           || "").trim();
    const email        = (formData.get("email")          || "").trim();
    const country      = (formData.get("country")        || "").trim() || "Not provided";
    const countryCode  = (formData.get("country_code")   || "").trim();
    const phone        = (formData.get("phone_number")   || "").trim() || "Not provided";
    const message      = (formData.get("message")        || "").trim();
    const turnstileToken = formData.get("cf-turnstile-response");

    // ============================================================
    // 2. TURNSTILE CAPTCHA VERIFICATION
    // ============================================================
    if (!turnstileToken) {
      return new Response("Please complete the security check.", { status: 400 });
    }

    if (!context.env.TURNSTILE_SECRET) {
      console.error("TURNSTILE_SECRET env var is not set.");
      return new Response("Server configuration error.", { status: 500 });
    }

    const turnstileRes = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body: new URLSearchParams({
          secret:   context.env.TURNSTILE_SECRET,
          response: turnstileToken,
          remoteip: context.request.headers.get("CF-Connecting-IP") || "",
        }),
      }
    );

    const turnstileOut = await turnstileRes.json();
    if (!turnstileOut.success) {
      console.error("Turnstile failed:", turnstileOut["error-codes"]);
      return new Response("Security verification failed, please retry.", { status: 400 });
    }

    // ============================================================
    // 3. BUILD FULL PHONE NUMBER
    // ============================================================
    let fullPhone = "Not provided";
    if (countryCode && phone !== "Not provided") {
      fullPhone = countryCode + phone;
    }

    // ============================================================
    // 4. INPUT VALIDATION
    // ============================================================
    const errors = [];

    // Name: required, 2-60 chars, letters/spaces/apostrophes/hyphens only
    if (!fullName) {
      errors.push("Full name is required");
    } else if (fullName.length < 2 || fullName.length > 60) {
      errors.push("Name must be between 2 and 60 characters");
    } else if (!/^[A-Za-zÀ-ÖØ-öø-ÿ\s'\-]+$/.test(fullName)) {
      errors.push("Name contains invalid characters");
    }

    // Email: required, valid format, max 120 chars
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email) {
      errors.push("Email address is required");
    } else if (email.length > 120) {
      errors.push("Email address is too long (max 120 characters)");
    } else if (!emailRegex.test(email)) {
      errors.push("Please enter a valid email address");
    }

    // Phone: optional, but if provided must be 6-20 digits
    if (phone !== "Not provided" && !/^[0-9]{6,20}$/.test(phone)) {
      errors.push("Phone number must contain 6-20 digits only");
    }

    // Message: required, 10-1200 chars
    if (!message) {
      errors.push("Message content is required");
    } else if (message.length < 10) {
      errors.push("Message must be at least 10 characters");
    } else if (message.length > 1200) {
      errors.push("Message is too long (max 1200 characters)");
    }

    if (errors.length > 0) {
      return new Response(`${errors.join(" | ")}`, { status: 400 });
    }

    // ============================================================
    // 5. SANITIZE INPUTS FOR EMAIL (prevent XSS in HTML body)
    // ============================================================
    function escapeHtml(str) {
      return String(str)
        .replaceAll("&",  "&amp;")
        .replaceAll("<",  "&lt;")
        .replaceAll(">",  "&gt;")
        .replaceAll('"',  "&quot;")
        .replaceAll("'",  "&#039;");
    }

    const escapedName     = escapeHtml(fullName);
    const escapedEmail    = escapeHtml(email);
    const escapedCountry  = escapeHtml(country);
    const escapedPhone    = escapeHtml(fullPhone);
    const escapedMessage  = escapeHtml(message).replaceAll("\n", "<br>");

    // ============================================================
    // 6. SEND EMAIL VIA CLOUDFLARE SEND EMAIL BINDING (SEBD)
    // ============================================================
    if (!context.env.SEBD) {
      console.error("SEBD binding is not configured.");
      return new Response("Server configuration error.", { status: 500 });
    }

    try {
      await context.env.SEBD.send({
        from:     "info@adaatrading.com",
        to:       "brahimethmane69@gmail.com",
        replyTo:  email,
        subject:  `New Contact Form Submission from ${fullName}`,
        html: `
          <h2>📬 New Message from your Website</h2>
          <p><strong>Name:</strong> ${escapedName}</p>
          <p><strong>Email:</strong> ${escapedEmail}</p>
          <p><strong>Country:</strong> ${escapedCountry}</p>
          <p><strong>Phone:</strong> ${escapedPhone}</p>
          <p><strong>Message:</strong><br>${escapedMessage}</p>
        `,
      });
    } catch (sendErr) {
      console.error("SEBD send failed:", sendErr);
      return new Response(
        "Could not send email. Please try again later or email us directly at info@adaatrading.com.",
        { status: 500 }
      );
    }

    // ============================================================
    // 7. SUCCESS RESPONSE
    // ============================================================
    return new Response(
      `✅Thank you, ${fullName}! Your message has been sent. We will reply within 24 hours.`,
      { status: 200 }
    );

  } catch (err) {
    console.error("Form handler exception:", err);
    return new Response("Server error, please try again.", { status: 500 });
  }
};
