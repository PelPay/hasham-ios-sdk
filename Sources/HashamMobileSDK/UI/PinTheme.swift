import UIKit

/// Configuration for the SDK-rendered PIN entry overlay.
public struct PinTheme {

    // MARK: - Colors

    public struct Colors {
        public var primary:        UIColor
        public var background:     UIColor
        public var surface:        UIColor
        public var keyBackground:  UIColor
        public var keyText:        UIColor
        public var dotFilled:      UIColor
        public var dotEmpty:       UIColor
        public var titleColor:     UIColor
        public var subtitleColor:  UIColor

        public init(
            primary:       UIColor = UIColor(red: 1.0, green: 0.42, blue: 0,   alpha: 1),
            background:    UIColor = .systemBackground,
            surface:       UIColor = .secondarySystemBackground,
            keyBackground: UIColor = .secondarySystemBackground,
            keyText:       UIColor = .label,
            dotFilled:     UIColor = UIColor(red: 1.0, green: 0.42, blue: 0, alpha: 1),
            dotEmpty:      UIColor = .systemGray4,
            titleColor:    UIColor = .label,
            subtitleColor: UIColor = .secondaryLabel
        ) {
            self.primary       = primary
            self.background    = background
            self.surface       = surface
            self.keyBackground = keyBackground
            self.keyText       = keyText
            self.dotFilled     = dotFilled
            self.dotEmpty      = dotEmpty
            self.titleColor    = titleColor
            self.subtitleColor = subtitleColor
        }
    }

    // MARK: - Typography

    public struct Typography {
        public var titleSize:    CGFloat
        public var subtitleSize: CGFloat
        public var keySize:      CGFloat
        public var fontName:     String?

        public init(
            titleSize:    CGFloat = 20,
            subtitleSize: CGFloat = 14,
            keySize:      CGFloat = 24,
            fontName:     String? = nil
        ) {
            self.titleSize    = titleSize
            self.subtitleSize = subtitleSize
            self.keySize      = keySize
            self.fontName     = fontName
        }

        func font(size: CGFloat, weight: UIFont.Weight = .regular) -> UIFont {
            if let name = fontName, let f = UIFont(name: name, size: size) { return f }
            return UIFont.systemFont(ofSize: size, weight: weight)
        }
    }

    // MARK: - Shape

    public struct Shape {
        public enum KeyShape { case circle, rounded, square }
        public var keyShape:      KeyShape
        public var cornerRadius:  CGFloat

        public init(keyShape: KeyShape = .circle, cornerRadius: CGFloat = 8) {
            self.keyShape     = keyShape
            self.cornerRadius = cornerRadius
        }
    }

    // MARK: - Strings

    public struct Strings {
        public var title:    String
        public var subtitle: String

        public init(
            title:    String = "Enter your PIN",
            subtitle: String = "Keep your PIN private"
        ) {
            self.title    = title
            self.subtitle = subtitle
        }
    }

    // MARK: - PinTheme

    public var colors:     Colors
    public var typography: Typography
    public var shape:      Shape
    public var strings:    Strings

    public init(
        colors:     Colors     = Colors(),
        typography: Typography = Typography(),
        shape:      Shape      = Shape(),
        strings:    Strings    = Strings()
    ) {
        self.colors     = colors
        self.typography = typography
        self.shape      = shape
        self.strings    = strings
    }
}
