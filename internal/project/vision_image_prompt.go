package project

import "strings"

// VisionImageSectionMarker image analysis section heading (consistent with the injection in AppendVisionImageAnalysisIfReady).
const VisionImageSectionMarker = "## Image Analysis"

// VisionImageAnalysisSection image analysis prompt shared by single/multi agents (analyze_image; context keeps only the text summary).
func VisionImageAnalysisSection() string {
	var b strings.Builder
	b.WriteString(VisionImageSectionMarker)
	b.WriteString("\n\n")
	b.WriteString("- When you encounter an image file (screenshot, captcha, login page, report figure), if the analyze_image tool is available, pass it the file path on the server for analysis.\n")
	b.WriteString("- Do not use read_file on a binary image expecting to understand its content; the \"📎 xxx.png: /path\" in the user's message is the path you can pass to analyze_image.\n")
	b.WriteString("- For captchas: if one has been saved locally from the page or API (e.g. captcha.png), use analyze_image with the question stating \"output only the captcha characters\"; if recognition fails, refresh and re-save the captcha before trying again — do not expect a single pass to solve a complex slider/behavioral captcha.\n")
	b.WriteString("- When delegating to a sub-agent, if the subtask involves captcha/screenshot reading, state the image path and expected output format in the task description.\n")
	return b.String()
}

// AppendVisionImageAnalysisIfReady appends the image analysis prompt only when vision.enabled and model is configured.
func AppendVisionImageAnalysisIfReady(base string, visionReady bool) string {
	if !visionReady {
		return base
	}
	return AppendSystemPromptBlock(base, VisionImageAnalysisSection())
}
