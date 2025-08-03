import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Star, MessageSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { StarRating } from "@/components/ui/star-rating";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface QuickRatingProps {
  productId: number;
  productName: string;
  onReviewSubmitted?: () => void;
}

export function QuickRating({ productId, productName, onReviewSubmitted }: QuickRatingProps) {
  const [showForm, setShowForm] = useState(false);
  const [rating, setRating] = useState(0);
  const [comment, setComment] = useState("");

  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const submitRatingMutation = useMutation({
    mutationFn: (data: any) => 
      apiRequest("/api/reviews", {
        method: "POST",
        body: JSON.stringify(data)
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/products", productId] });
      setShowForm(false);
      setRating(0);
      setComment("");
      onReviewSubmitted?.();
      toast({
        title: "Rating submitted",
        description: "Thank you for your feedback!"
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to submit rating",
        variant: "destructive"
      });
    }
  });

  const handleSubmit = () => {
    if (!user) {
      toast({
        title: "Login required",
        description: "Please login to rate this product",
        variant: "destructive"
      });
      return;
    }

    if (rating === 0) {
      toast({
        title: "Rating required",
        description: "Please select a rating",
        variant: "destructive"
      });
      return;
    }

    submitRatingMutation.mutate({
      productId,
      customerId: user.id,
      rating,
      comment: comment.trim() || null
    });
  };

  if (!user) {
    return null;
  }

  return (
    <Card className="border-dashed">
      <CardContent className="p-4">
        {!showForm ? (
          <div className="text-center">
            <Button
              variant="outline"
              onClick={() => setShowForm(true)}
              className="gap-2"
            >
              <Star className="h-4 w-4" />
              Rate this product
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="text-center">
              <p className="text-sm font-medium mb-2">Rate {productName}</p>
              <StarRating
                rating={rating}
                onRatingChange={setRating}
                size="lg"
                className="justify-center"
              />
            </div>

            <div>
              <Textarea
                placeholder="Share your thoughts (optional)..."
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>

            <div className="flex gap-2">
              <Button 
                onClick={handleSubmit}
                disabled={submitRatingMutation.isPending || rating === 0}
                className="flex-1"
              >
                {submitRatingMutation.isPending ? "Submitting..." : "Submit Rating"}
              </Button>
              <Button 
                variant="outline" 
                onClick={() => {
                  setShowForm(false);
                  setRating(0);
                  setComment("");
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}