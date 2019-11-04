const { DOM_TAGS, SVG_TAGS } = require('./constants');

function isUpperCase(str) {
  return /^[A-Z_-]+$/.test(str);
}

function isNativeDOMTag(str) {
  return DOM_TAGS.includes(str);
}

function isSvgTag(str) {
  return SVG_TAGS.includes(str);
}

const blacklistAttrs = ['placeholder', 'alt', 'aria-label', 'value'];
function isAllowedDOMAttr(tag, attr) {
  if (isSvgTag(tag)) return true;
  if (isNativeDOMTag(tag)) {
    return !blacklistAttrs.includes(attr);
  }
  return false;
}

exports.isUpperCase = isUpperCase;
exports.isAllowedDOMAttr = isAllowedDOMAttr;
