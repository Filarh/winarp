package com.winarp.mobile.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColors = darkColorScheme(
    primary = Accent,
    onPrimary = Color.White,
    secondary = Mint,
    onSecondary = Color(0xFF042016),
    tertiary = Warning,
    background = NightBg,
    onBackground = TextPrimary,
    surface = NightSurface,
    onSurface = TextPrimary,
    surfaceVariant = NightCard,
    onSurfaceVariant = TextSecondary,
    error = Danger,
    onError = Color.White,
    outline = Stroke
)

@Composable
fun WinArpTheme(content: @Composable () -> Unit) {
    // Force a consistent premium dark look on mobile.
    MaterialTheme(
        colorScheme = DarkColors,
        typography = Typography,
        content = content
    )
}
