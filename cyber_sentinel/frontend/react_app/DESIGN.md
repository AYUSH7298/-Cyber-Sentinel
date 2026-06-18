---
name: RAKSHAK Command Portal
colors:
  surface: '#101415'
  surface-dim: '#101415'
  surface-bright: '#363a3b'
  surface-container-lowest: '#0b0f10'
  surface-container-low: '#191c1e'
  surface-container: '#1d2022'
  surface-container-high: '#272a2c'
  surface-container-highest: '#323537'
  on-surface: '#e0e3e5'
  on-surface-variant: '#bbc9cd'
  inverse-surface: '#e0e3e5'
  inverse-on-surface: '#2d3133'
  outline: '#859397'
  outline-variant: '#3c494c'
  surface-tint: '#2fd9f4'
  primary: '#8aebff'
  on-primary: '#00363e'
  primary-container: '#22d3ee'
  on-primary-container: '#005763'
  inverse-primary: '#006877'
  secondary: '#ffb3ad'
  on-secondary: '#68000a'
  secondary-container: '#a40217'
  on-secondary-container: '#ffaea8'
  tertiary: '#d5dcf6'
  on-tertiary: '#283044'
  tertiary-container: '#b9c0da'
  on-tertiary-container: '#474e64'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#a2eeff'
  primary-fixed-dim: '#2fd9f4'
  on-primary-fixed: '#001f25'
  on-primary-fixed-variant: '#004e5a'
  secondary-fixed: '#ffdad7'
  secondary-fixed-dim: '#ffb3ad'
  on-secondary-fixed: '#410004'
  on-secondary-fixed-variant: '#930013'
  tertiary-fixed: '#dae2fd'
  tertiary-fixed-dim: '#bec6e0'
  on-tertiary-fixed: '#131b2e'
  on-tertiary-fixed-variant: '#3f465c'
  background: '#101415'
  on-background: '#e0e3e5'
  surface-variant: '#323537'
typography:
  display-lg:
    fontFamily: Outfit
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Outfit
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
  headline-lg-mobile:
    fontFamily: Outfit
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-md:
    fontFamily: Outfit
    fontSize: 24px
    fontWeight: '500'
    lineHeight: 32px
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  label-mono:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  unit: 4px
  gutter: 24px
  margin-desktop: 40px
  margin-mobile: 16px
  container-max-width: 1600px
---

## Brand & Style
The design system establishes a high-fidelity, high-stakes environment for cybersecurity professionals. It prioritizes clarity and immediate visual feedback through a "Tactical Glassmorphism" aesthetic. The interface must feel like a sophisticated command center—immersive, precise, and authoritative. 

The visual language balances deep, expansive voids with sharp, luminous data points to evoke a sense of vigilance and technological superiority. Every element is designed to feel like a high-end heads-up display (HUD), utilizing transparency and light-refraction to create depth without visual clutter.

## Colors
The palette is rooted in a "Deep Space" hierarchy. The primary background uses a rich Navy-Black (#020617) to provide maximum contrast for glowing elements. 

- **Primary Cyan (#22D3EE):** Used for "Secure" states, primary actions, and active scanning. It should emit a soft glow effect (outer glow) in high-priority data visualizations.
- **Warning Crimson (#EF4444):** Reserved strictly for alerts, critical threats, and high-risk anomalies. 
- **Surface Navy (#0F172A):** Used for card backgrounds with 60-80% opacity to facilitate glassmorphism.
- **Accents:** Utilize subtle violet or indigo tints for inactive states to maintain the cool, tech-focused temperature.

## Typography
The system employs a dual-font strategy. **Outfit** provides a modern, geometric feel for headlines and large data points, conveying a sense of forward-thinking technology. **Inter** is used for all functional body text and interface controls to ensure maximum legibility at smaller scales. **JetBrains Mono** is introduced for technical labels, IP addresses, and code snippets to reinforce the "cyber" and "terminal" nature of the product. Use uppercase styling for labels and status badges to increase their tactical appearance.

## Layout & Spacing
The layout follows a strict 12-column fluid grid on desktop. It prioritizes information density without overcrowding. 

- **Grid:** Use a 24px gutter to allow the glassmorphic "glow" of cards to breathe without overlapping adjacent elements.
- **Sidebar:** A fixed 280px left navigation rail that uses a high-blur backdrop.
- **Mobile:** Transition to a single-column layout with 16px side margins. Cards should lose their outer glow on mobile to preserve performance and screen real estate.
- **Rhythm:** All spacing (padding, margins) should be multiples of 4px.

## Elevation & Depth
Depth is achieved through layering and transparency rather than traditional heavy shadows.
- **The Glass Layer:** All cards use a background of `#0F172A` at 70% opacity with a `backdrop-filter: blur(12px)`.
- **Borders:** Surfaces must have a 1px solid border. Use a linear gradient for borders: `top-left: white/20%` to `bottom-right: white/5%`.
- **Glows:** Instead of black shadows, use "Atmospheric Glows." A critical alert card should have a soft `#EF4444` drop-shadow with a 20px blur and only 15% opacity to simulate light emitting from the screen.

## Shapes
The UI uses a consistent "Rounded" profile to soften the technical edge and make the interface feel modern and premium. 
- **Standard Cards:** 0.5rem (8px) radius.
- **Buttons & Chips:** 1rem (16px) for a slightly more ergonomic, pill-like feel.
- **Inputs:** 0.5rem (8px).
- **Interactive States:** Hovering over a card should trigger a slight scale-up (1.02x) and an increase in the border's opacity.

## Components
- **Buttons:** Primary buttons use a solid Cyan (#22D3EE) fill with dark text. Ghost buttons use the gradient border technique with Cyan text.
- **Status Indicators:** Use pulsing animations for "Active Threats." A small 8px circle that pulses between 40% and 100% opacity.
- **Glassmorphic Cards:** The core container. Must include the 1px gradient border and backdrop blur.
- **Risk Progress Bars:** Thin 4px tracks. The "filled" portion should have a CSS `box-shadow` of the same color to create a "neon tube" effect.
- **Data Badges:** Small, condensed labels with JetBrains Mono. 
    - *Malware:* Crimson background (20% opacity) / Crimson text.
    - *Safe:* Cyan background (20% opacity) / Cyan text.
- **Sidebar Navigation:** Transparent background. Active items receive a Cyan vertical "light bar" on the far left and a subtle background glow.