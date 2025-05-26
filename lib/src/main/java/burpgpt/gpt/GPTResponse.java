package burpgpt.gpt;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.annotations.SerializedName;

import lombok.Getter;

@Getter
public class GPTResponse {
    private List<Choice> choices;
    private String model;
    private String id;
    @SerializedName("created")
    private long createdTimestamp;
    @SerializedName("usage")
    private Usage usage;
    @SerializedName("error")
    private ErrorInfo error;

    public GPTResponse(List<Choice> choices) {
        this.choices = choices;
    }

    @Getter
    public class Choice {
        private String text;
        private int index;
        private Object logprobs;
        @SerializedName("finish_reason")
        private String finishReason;
        @SerializedName("message")
        private Message message;

        public String getText() {
            // Support both completion API and chat API formats
            if (message != null && message.getContent() != null) {
                return message.getContent();
            }
            return text;
        }

        @Override
        public String toString() {
            return "Choice{" +
                    "text='" + getText() + '\'' +
                    ", index=" + index +
                    ", logprobs=" + logprobs +
                    ", finishReason='" + finishReason + '\'' +
                    '}';
        }
    }

    @Getter
    public static class Message {
        private String role;
        private String content;
    }

    public List<String> getChoiceTexts() {
        List<String> choiceTexts = new ArrayList<>();
        if (choices != null) {
            for (Choice choice : choices) {
                choiceTexts.add(choice.getText());
            }
        }
        return choiceTexts;
    }

    @Getter
    public static class Usage {
        @SerializedName("prompt_tokens")
        private long promptTokens;
        @SerializedName("completion_tokens")
        private long completionTokens;
        @SerializedName("total_tokens")
        private long totalTokens;

        @Override
        public String toString() {
            return "Usage{" +
                    "promptTokens=" + promptTokens +
                    ", completionTokens=" + completionTokens +
                    ", totalTokens=" + totalTokens +
                    '}';
        }
    }

    @Getter
    public static class ErrorInfo {
        private String message;
        private String type;
        private String code;

        @Override
        public String toString() {
            return "Error{" +
                    "message='" + message + '\'' +
                    ", type='" + type + '\'' +
                    ", code='" + code + '\'' +
                    '}';
        }
    }

    public boolean hasError() {
        return error != null;
    }

    public String getErrorMessage() {
        if (error != null && error.getMessage() != null) {
            return error.getMessage();
        }
        return "Unknown API error";
    }

    @Override
    public String toString() {
        return "GPTResponse{" +
                "choices=" + choices +
                ", model='" + model + '\'' +
                ", id='" + id + '\'' +
                ", createdTimestamp=" + createdTimestamp +
                ", usage=" + usage +
                ", error=" + error +
                '}';
    }
}
