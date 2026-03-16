import { assertSafeHtml } from '../security/safeHtml';

export default function SafeHtml({ value, as: As = 'div', ...rest }) {
  assertSafeHtml(value, { source: 'SafeHtmlComponent' });
  return <As {...rest} dangerouslySetInnerHTML={{ __html: value.html }} />;
}

